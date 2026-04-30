"""YARA rule engine — compile and match YARA rules against data and files."""

from __future__ import annotations


import asyncio
import io
import logging
import zipfile
from pathlib import Path

import aiohttp

from src.core.http_circuit import get_breaker

logger = logging.getLogger(__name__)

try:
    import yara  # type: ignore[import-untyped]

    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.warning(
        "yara-python is not installed — YARA matching will be unavailable. "
        "Install with: pip install yara-python"
    )


class YaraEngine:
    """Compile and match YARA rules against binary data or files.

    This is a local engine and does NOT inherit from BaseIntegration
    (no remote API involved).

    Adversarial audit D-19 — ``rules_dir`` must be confined to the
    install tree (``YARA_RULES_ROOT``). A misconfig like
    ``rules_dir=/etc/secrets`` would otherwise walk the host's secret
    directory and surface file contents in parse-failure logs.
    """

    COMMUNITY_RULES_URL = (
        "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
    )

    # Allowed parent directories for YARA rule loading. Must be absolute
    # paths. ``data/yara_rules`` is the bundled / dev path; the Docker
    # image installs into /opt/argus/rules/yara.
    _RULES_ROOTS: tuple[Path, ...] = (
        Path("/opt/argus/rules/yara").resolve(),
        Path.cwd().resolve() / "data" / "yara_rules",
    )

    def __init__(self, rules_dir: str = "data/yara_rules"):
        candidate = Path(rules_dir).expanduser().resolve()
        # Allow the path itself or any ancestor that lives under one of
        # the install roots. ``is_relative_to`` is the strict check.
        ok = any(
            candidate == root or candidate.is_relative_to(root)
            for root in self._RULES_ROOTS
        )
        if not ok:
            raise ValueError(
                f"YARA rules_dir must live under {self._RULES_ROOTS!r}; "
                f"got {candidate!r}"
            )
        self.rules_dir = candidate
        self._compiled: "yara.Rules | None" = None  # type: ignore[name-defined]

    def compile_rules(self) -> int:
        """Scan rules_dir for .yar/.yara files and compile a combined ruleset.

        Returns:
            Number of rule files compiled.
        """
        if not _YARA_AVAILABLE:
            logger.warning("yara-python not installed — skipping compile.")
            return 0

        if not self.rules_dir.exists():
            logger.warning("Rules directory does not exist: %s", self.rules_dir)
            return 0

        all_files: dict[str, str] = {}
        for ext in ("*.yar", "*.yara"):
            for path in self.rules_dir.rglob(ext):
                namespace = str(path.relative_to(self.rules_dir)).replace("/", "_").replace("\\", "_")
                all_files[namespace] = str(path)

        if not all_files:
            logger.info("No YARA rule files found in %s", self.rules_dir)
            self._compiled = None
            return 0

        # Try bulk compile first — fastest path
        try:
            self._compiled = yara.compile(filepaths=all_files)
            logger.info("Compiled %d YARA rule file(s) from %s", len(all_files), self.rules_dir)
            return len(all_files)
        except (yara.SyntaxError, Exception) as exc:
            logger.warning("Bulk compile failed (%s) — compiling rules individually", exc)

        # Fall back to per-file compilation, skipping broken rules
        good_files: dict[str, str] = {}
        skipped = 0
        for ns, filepath in all_files.items():
            try:
                yara.compile(filepath=filepath)
                good_files[ns] = filepath
            except (yara.SyntaxError, yara.Error, OSError) as exc:
                # Broken / malformed individual rule file. We skip and
                # log at DEBUG so a corpus refresh that introduces a
                # bad file is still visible without spamming INFO.
                skipped += 1
                logger.debug("Skipping unparseable YARA rule %s: %s", filepath, exc)

        if good_files:
            try:
                self._compiled = yara.compile(filepaths=good_files)
                logger.info(
                    "Compiled %d YARA rule file(s), skipped %d broken (%s)",
                    len(good_files), skipped, self.rules_dir,
                )
                return len(good_files)
            except (yara.SyntaxError, yara.Error, OSError) as exc:
                logger.error("Failed to compile good rules: %s", exc)

        self._compiled = None
        return 0

    def match_data(self, data: bytes, timeout: int = 30) -> list[dict]:
        """Match binary data against compiled rules.

        Args:
            data: Raw bytes to scan.
            timeout: Maximum seconds for the matching operation.

        Returns:
            List of match dicts with keys: rule, tags, meta, strings.
        """
        if not _YARA_AVAILABLE:
            logger.warning("yara-python not installed — returning empty results.")
            return []

        if self._compiled is None:
            logger.warning("No compiled YARA rules — call compile_rules() first.")
            return []

        try:
            matches = self._compiled.match(data=data, timeout=timeout)
        except yara.TimeoutError:
            logger.error("YARA match timed out after %ds", timeout)
            return []
        except yara.Error as exc:
            logger.error("YARA match_data failed: %s", exc)
            return []

        return self._format_matches(matches)

    def match_file(self, filepath: str) -> list[dict]:
        """Match a file on disk against compiled rules.

        Args:
            filepath: Path to the file to scan.

        Returns:
            List of match dicts with keys: rule, tags, meta, strings.
        """
        if not _YARA_AVAILABLE:
            logger.warning("yara-python not installed — returning empty results.")
            return []

        if self._compiled is None:
            logger.warning("No compiled YARA rules — call compile_rules() first.")
            return []

        target = Path(filepath)
        if not target.is_file():
            logger.error("File not found: %s", filepath)
            return []

        try:
            matches = self._compiled.match(filepath=str(target), timeout=30)
        except yara.TimeoutError:
            logger.error("YARA match timed out for file %s", filepath)
            return []
        except (yara.Error, OSError) as exc:
            logger.error("YARA match_file failed for %s: %s", filepath, exc)
            return []

        return self._format_matches(matches)

    async def sync_community_rules(self) -> None:
        """Download the latest YARA community rules from GitHub.

        Fetches the Yara-Rules/rules repo as a zip archive, extracts all
        .yar files into ``self.rules_dir``. ``aiohttp`` is a hard
        dependency of the project (see requirements.txt) so the import
        is module-level.
        """
        logger.info("Downloading YARA community rules from %s ...", self.COMMUNITY_RULES_URL)

        try:
            async with get_breaker("yara_community_rules"):
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.COMMUNITY_RULES_URL, timeout=aiohttp.ClientTimeout(total=120)) as resp:
                        if resp.status != 200:
                            logger.error(
                                "Failed to download community rules: HTTP %d", resp.status
                            )
                            return
                        archive_bytes = await resp.read()
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
            logger.error("Error downloading community rules: %s", exc)
            return

        self.rules_dir.mkdir(parents=True, exist_ok=True)
        extracted = 0

        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    name_lower = info.filename.lower()
                    if not (name_lower.endswith(".yar") or name_lower.endswith(".yara")):
                        continue

                    # Flatten into rules_dir, preserving only the filename
                    dest = self.rules_dir / Path(info.filename).name
                    dest.write_bytes(zf.read(info.filename))
                    extracted += 1
        except zipfile.BadZipFile:
            logger.error("Downloaded archive is not a valid zip file.")
            return
        except (OSError, zipfile.LargeZipFile) as exc:
            logger.error("Error extracting community rules: %s", exc)
            return

        logger.info(
            "Extracted %d YARA rule file(s) into %s", extracted, self.rules_dir
        )

    @staticmethod
    def _format_matches(matches: list) -> list[dict]:
        """Convert yara match objects into plain dicts."""
        results: list[dict] = []
        for m in matches:
            matched_strings: list[dict] = []
            for string_match in m.strings:
                for instance in string_match.instances:
                    matched_strings.append({
                        "offset": instance.offset,
                        "identifier": string_match.identifier,
                        "data": instance.matched_data.hex()
                        if isinstance(instance.matched_data, bytes)
                        else str(instance.matched_data),
                    })

            results.append({
                "rule": m.rule,
                "tags": list(m.tags),
                "meta": dict(m.meta),
                "strings": matched_strings,
            })
        return results
