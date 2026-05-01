# Exception-handling rules

This codifies the audit E13 disposition. Every new `except Exception:`
introduced in `src/` must follow one of three patterns; PR review
rejects anything else.

## Pattern A — Narrow to a specific exception type (preferred)

If the failure surface is bounded, name the exception types explicitly:

```python
try:
    body = await resp.text()
except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
    logger.warning("phishtank fetch failed: %s", e)
    return []
```

The library you are calling determines the union. Common ones:

| Library / boundary | Exception types |
|---|---|
| aiohttp HTTP client | `aiohttp.ClientError`, `asyncio.TimeoutError`, `OSError` |
| smtplib | `smtplib.SMTPException`, `OSError` |
| asyncpg / SQLAlchemy | `sqlalchemy.exc.SQLAlchemyError` (covers asyncpg subclasses) |
| boto3 / botocore | `botocore.exceptions.ClientError`, `BotoCoreError` |
| YARA | `yara.Error`, `yara.SyntaxError`, `yara.TimeoutError` |
| JSON parsing | `json.JSONDecodeError`, `ValueError` |
| GeoIP2 | `geoip2.errors.AddressNotFoundError`, `OSError` |
| Image decode | `PIL.UnidentifiedImageError`, `OSError` |
| ZIP archives | `zipfile.BadZipFile`, `zipfile.LargeZipFile`, `OSError` |

## Pattern B — Boundary code that MUST NOT raise (justified-broad)

A handful of call sites are at trust boundaries where catching
everything is the correct design — letting an exception bubble would
break worse-than-the-current-failure invariants. Examples:

* The notification dispatch loop must protect itself from one
  channel's adapter blowing up so the others still send.
* A worker tick must not let a per-org failure crash the loop and
  freeze every other org's processing.
* `auto_link_finding` must never roll back the finding insert if the
  notification or case-creation leg fails.

In these cases use:

```python
except Exception as e:  # noqa: BLE001
    # One-line reason for why broad catch is the right design here.
    logger.exception("notify dispatch: adapter %s raised", channel.kind)
```

The `# noqa: BLE001` MUST be accompanied by a comment that explains
the boundary. Lint rules check for the noqa; reviewers check for the
comment.

## Pattern C — Best-effort cleanup (justified-broad)

Cleanups in `finally` blocks, transport teardown, and Redis key
deletion that would otherwise cascade an upstream error need broad
catch. Same `# noqa: BLE001` convention:

```python
try:
    client.quit()
except (smtplib.SMTPException, OSError):
    # Server already closed the connection; quit() failure isn't
    # actionable — message was sent successfully.
    pass
```

When the cleanup itself has a bounded failure surface, prefer narrow
exceptions even here (the example above narrows to two types instead
of `Exception`).

## What is NOT allowed

```python
except Exception:                # No justification, no logging.
    pass
```

```python
except Exception as e:           # Catch + swallow without logging.
    return []
```

```python
except Exception:                # Catch then re-raise — pointless.
    raise
```

If the right answer is "catch and log", do that explicitly. If the
right answer is "let it propagate", remove the try.

## Enforcement

* Pre-merge: ruff's `BLE001` rule fires on bare `except Exception:`.
  PRs add `# noqa: BLE001` only where Pattern B or C applies, with a
  comment.
* Audit: `grep -rn "except Exception" src/ | grep -v "# noqa: BLE001"`
  must return zero hits in `src/` (test fixtures may differ).
* The fault-injection suite in `tests/fault_injection/` exercises
  several of these boundaries — a regression that swaps a narrow
  catch for a broad one will fail one of those tests.

## Audit close-out (E13)

| Files swept | Sites narrowed | Sites justified-broad |
|---|---|---|
| `src/takedown/adapters.py` | 5 | 1 |
| `src/integrations/yara_engine/engine.py` | 6 | 0 |
| `src/intel/phishing_feeds.py` | 5 | 0 |
| `src/feeds/geolocation.py` | 5 | 0 |
| `src/feeds/base.py` | 2 (added classification) | 0 |
| `src/agents/feed_triage.py` | 1 (SQLAlchemyError) | 3 |
| `src/agents/triage_agent.py` | — | 4 (already justified) |
| `src/brand/classifier.py` | 1 | 0 |
| `src/core/auth_policy.py` | 1 | 0 |
| `src/crawlers/{matrix,forum,telegram}_crawler.py` | 4 | 0 |
| `src/enrichment/ioc_extractor.py` | 1 | 0 |
| `src/api/routes/evidence.py` | — | 2 (MIME sniff, with logging+metric) |
| `src/workers/runner.py` | — | 11 (top-level loop boundaries) |
| `src/notifications/{router,adapters}.py` | — | 6 (dispatch loop boundary) |
| `src/social/*_monitor.py` | — | 16 (per-handle isolation; loaders raise many types) |
| `src/brand/probe.py` | — | 3 (degrade-gracefully on storage failure) |

**Net:** 31 sites narrowed to explicit exception types; ~50 sites
justified-broad with `# noqa: BLE001` + explanatory comment + logging.
The audit's "113 except Exception blocks" headline is now resolved —
every production site is either narrow or justified.
