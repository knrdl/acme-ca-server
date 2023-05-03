from . import middleware  # noqa: F401 (import required as module export)
from . import router as router_module

router = router_module.api
