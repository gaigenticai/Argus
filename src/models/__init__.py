"""Models package.

Most code imports models by their fully-qualified module
(``from src.models.intel import IOC``); a few callers — Base.metadata
helpers, alembic, the seed package — only ``import src.models`` and
expect every table to be registered on ``Base.metadata``.

Touch each module here so that side-effect-import is enough to make
the full schema discoverable. Add new model modules to this list when
they introduce new tables.
"""

from . import investigations  # noqa: F401 — register Investigation table
from . import brand_actions  # noqa: F401 — register BrandAction table
from . import case_copilot  # noqa: F401 — register CaseCopilotRun table
from . import threat_hunts  # noqa: F401 — register ThreatHuntRun table
from . import org_agent_settings  # noqa: F401 — register agent settings
from . import compliance  # noqa: F401 — register compliance tables (P1 #1.3)
from . import d3fend_oscal  # noqa: F401 — register D3FEND + OSCAL tables (P2 #2.12)
from . import feed_subscription  # noqa: F401 — P3 #3.4 user-self-service feeds
from . import oss_tool  # noqa: F401 — admin-onboarding OSS-tool install state
from . import playbooks  # noqa: F401 — exec-briefing playbook execution audit
from . import advisory_health  # noqa: F401 — advisory ingest health
from . import agent_task  # noqa: F401 — Bridge-LLM agent task queue (governance)
from . import dmarc_forensic  # noqa: F401 — RUF + IMAP mailbox config
from . import notification_inbox  # noqa: F401 — in-app inbox
from . import dsar  # noqa: F401 — data-subject-access-request workflow
from . import learnings  # noqa: F401 — pre-purge knowledge log
from . import evidence_audit  # noqa: F401 — Merkle audit chain
