import asyncio
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .account import router as account_router
from .authorization import router as authorization_router
from .certificate import cronjob as certificate_cronjob
from .certificate import router as certificate_router
from .challenge import router as challenge_router
from .directory import router as directory_router
from .nonce import cronjob as nonce_cronjob
from .nonce import router as nonce_router
from .order import router as order_router


class ACMEResponse(JSONResponse):
    def render(self, content: dict[str, Any] | None) -> bytes:
        return super().render(  # remove null fields from responses
            {k: v for k, v in content.items() if v is not None} if content is not None else None
        )


router = APIRouter(prefix='/acme', default_response_class=ACMEResponse)
router.include_router(account_router.api)
router.include_router(authorization_router.api)
router.include_router(certificate_router.api)
router.include_router(challenge_router.api)
router.include_router(directory_router.api)
router.include_router(nonce_router.api)
router.include_router(order_router.api)


async def start_cronjobs():
    await asyncio.gather(
        certificate_cronjob.start(),
        nonce_cronjob.start(),
    )
