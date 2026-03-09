"""GitHub crawler — monitors for code leaks, exposed secrets, and PoC exploits."""

import json
import logging
from datetime import datetime, timezone
from typing import AsyncIterator
from urllib.parse import quote

from src.models.threat import SourceType
from .base import BaseCrawler, CrawlResult

logger = logging.getLogger(__name__)


class GitHubCrawler(BaseCrawler):
    """Searches GitHub for leaked credentials, secrets, and exploit PoCs."""

    name = "github_crawler"
    source_type = SourceType.GITHUB

    SEARCH_API = "https://api.github.com/search/code"
    REPO_SEARCH_API = "https://api.github.com/search/repositories"

    # Patterns that indicate leaked secrets
    SECRET_DORKS = [
        '"{domain}" password',
        '"{domain}" api_key',
        '"{domain}" secret_key',
        '"{domain}" aws_access_key',
        '"{domain}" private_key',
        '"{domain}" jdbc:',
        '"{domain}" connectionString',
    ]

    # Patterns for exploit PoCs
    EXPLOIT_DORKS = [
        "CVE-{cve_id} exploit",
        "CVE-{cve_id} poc",
        "CVE-{cve_id} payload",
    ]

    def __init__(self, github_token: str | None = None):
        super().__init__()
        self.github_token = github_token

    async def _get_headers(self) -> dict:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"
        return headers

    async def crawl_for_org(self, domains: list[str], keywords: list[str]) -> AsyncIterator[CrawlResult]:
        """Search GitHub for leaks related to an organization."""
        for domain in domains:
            for dork_template in self.SECRET_DORKS:
                query = dork_template.format(domain=domain)
                async for result in self._search_code(query, domain):
                    yield result
                await self._delay()

        for keyword in keywords:
            query = f'"{keyword}" password OR secret OR api_key'
            async for result in self._search_code(query, keyword):
                yield result
            await self._delay()

    async def crawl_for_cve(self, cve_ids: list[str]) -> AsyncIterator[CrawlResult]:
        """Search GitHub for PoC exploits for specific CVEs."""
        for cve_id in cve_ids:
            for dork_template in self.EXPLOIT_DORKS:
                query = dork_template.format(cve_id=cve_id)
                async for result in self._search_repos(query, cve_id):
                    yield result
                await self._delay()

    async def crawl(self) -> AsyncIterator[CrawlResult]:
        # Generic crawl — searches for recent exploit repos
        query = "exploit poc CVE-2024 OR CVE-2025 OR CVE-2026"
        async for result in self._search_repos(query, "recent_exploits"):
            yield result

    async def _search_code(self, query: str, context: str) -> AsyncIterator[CrawlResult]:
        url = f"{self.SEARCH_API}?q={quote(query)}&per_page=30&sort=indexed&order=desc"
        session = await self._get_session()
        headers = await self._get_headers()

        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status == 403:
                    logger.warning(f"[{self.name}] GitHub rate limit hit")
                    return
                if resp.status != 200:
                    return

                data = await resp.json()

            for item in data.get("items", []):
                repo = item.get("repository", {})
                yield CrawlResult(
                    source_type=self.source_type,
                    source_url=item.get("html_url"),
                    source_name="GitHub Code Search",
                    title=f"Potential leak in {repo.get('full_name', 'unknown')}",
                    content=f"File: {item.get('path')}\nRepo: {repo.get('full_name')}\nQuery: {query}",
                    author=repo.get("owner", {}).get("login"),
                    raw_data={
                        "file_path": item.get("path"),
                        "repo": repo.get("full_name"),
                        "search_query": query,
                        "search_context": context,
                    },
                )
        except Exception as e:
            logger.error(f"[{self.name}] GitHub code search failed: {e}")

    async def _search_repos(self, query: str, context: str) -> AsyncIterator[CrawlResult]:
        url = f"{self.REPO_SEARCH_API}?q={quote(query)}&per_page=30&sort=updated&order=desc"
        session = await self._get_session()
        headers = await self._get_headers()

        try:
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()

            for repo in data.get("items", []):
                created = repo.get("created_at")
                published_at = None
                if created:
                    try:
                        published_at = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    except ValueError:
                        pass

                yield CrawlResult(
                    source_type=self.source_type,
                    source_url=repo.get("html_url"),
                    source_name="GitHub Repo Search",
                    title=repo.get("full_name"),
                    content=f"Repo: {repo.get('full_name')}\nDescription: {repo.get('description', 'N/A')}\nStars: {repo.get('stargazers_count', 0)}\nQuery: {query}",
                    author=repo.get("owner", {}).get("login"),
                    published_at=published_at,
                    raw_data={
                        "repo": repo.get("full_name"),
                        "stars": repo.get("stargazers_count", 0),
                        "language": repo.get("language"),
                        "search_context": context,
                    },
                )
        except Exception as e:
            logger.error(f"[{self.name}] GitHub repo search failed: {e}")
