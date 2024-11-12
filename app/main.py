__version__ = "0.0.0"  # replaced during build, do not change

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError

from . import acme
from . import ca
from . import db

from . import web


from .acme.exceptions import ACMEException
from .config import settings


@asynccontextmanager
async def lifespan(_: FastAPI):
    await db.connect()
    await db.migrations.run()
    await ca.init()
    await acme.start_cronjobs()
    yield
    await db.disconnect()


app = FastAPI(
    lifespan=lifespan,
    version=__version__,
    redoc_url=None,
    docs_url=None,
    title=settings.web.app_title,
    description=settings.web.app_description,
)
app.add_middleware(
    web.middleware.SecurityHeadersMiddleware,
    content_security_policy={
        "/acme/": "base-uri 'self'; default-src 'none';",
        "/endpoints": "base-uri 'self'; default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-src 'none'; img-src 'self' data:;",
        "/": "base-uri 'self'; default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-src 'none'; img-src 'self' data:;",
    },
)


if settings.web.enabled:

    @app.get("/endpoints", tags=["web"])
    async def swagger_ui_html():
        return get_swagger_ui_html(
            openapi_url="/openapi.json",
            title=app.title,
            swagger_favicon_url="favicon.png",
            swagger_css_url="libs/swagger-ui.css",
            swagger_js_url="libs/swagger-ui-bundle.js",
        )


@app.exception_handler(RequestValidationError)
@app.exception_handler(HTTPException)
@app.exception_handler(ACMEException)
@app.exception_handler(Exception)
async def acme_exception_handler(request: Request, exc: Exception):
    # custom exception handler for acme specific response format
    if request.url.path.startswith("/acme/") or isinstance(exc, ACMEException):
        if isinstance(exc, ACMEException):
            return await exc.as_response()
        elif isinstance(exc, ValidationError):
            return await ACMEException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                exctype="malformed",
                detail=exc.json(),
            ).as_response()
        elif isinstance(exc, HTTPException):
            return await ACMEException(
                status_code=exc.status_code,
                exctype="serverInternal",
                detail=str(exc.detail),
            ).as_response()
        else:
            return await ACMEException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                exctype="serverInternal",
                detail=str(exc),
            ).as_response()
    else:
        if isinstance(exc, HTTPException):
            return await http_exception_handler(request, exc)
        else:
            return JSONResponse(
                {"detail": str(exc)}, status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


app.include_router(acme.router)
app.include_router(
    acme.directory_router.api
)  # serve acme directory under /acme/directory and /directory
app.include_router(ca.router)

if settings.web.enabled:
    app.include_router(web.router)

    if Path("/app/web/www").exists():
        app.mount("/", StaticFiles(directory="/app/web/www"), name="static")
