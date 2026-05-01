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
