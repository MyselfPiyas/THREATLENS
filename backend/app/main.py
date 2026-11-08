import logging
import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi.encoders import jsonable_encoder
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.responses import Response

from app.api.auth import router as auth_router
from app.api.health import router as health_router
from app.api.identity import router as identity_router
from app.api.tls import router as tls_router
from app.api.analysis import router as analysis_router
from app.api.scans import router as scans_router
from app.api.intelligence import router as intelligence_router
from app.api.passports import router as passports_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.services.scan_queue import scan_queue

logger = logging.getLogger("threatlens.api")
settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    logger.info("Starting %s in %s mode", settings.app_name, settings.app_env)
    await scan_queue.start()
    try:
        yield
    finally:
        await scan_queue.stop()
        logger.info("Stopping %s", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    description="THREATLENS authenticated URL investigation API.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    max_age=600,
)


@app.middleware("http")
async def log_requests(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
    logger.info("%s %s %s %.2fms", request.method, request.url.path, response.status_code, elapsed_ms)
    return response


@app.exception_handler(RequestValidationError)
async def handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    safe_errors = [
        {
            "location": [str(part) for part in error.get("loc", ())],
            "type": error.get("type", "validation_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={"detail": "Request validation failed.", "errors": jsonable_encoder(safe_errors)},
    )


@app.exception_handler(Exception)
async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    logger.error(
        "Unhandled request error for %s %s",
        request.method,
        request.url.path,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred."},
    )


app.include_router(health_router)
app.include_router(health_router, prefix="/api/v1")
app.include_router(auth_router, prefix="/api/v1")
app.include_router(scans_router, prefix="/api/v1")
app.include_router(identity_router, prefix="/api/v1")
app.include_router(tls_router, prefix="/api/v1")
app.include_router(analysis_router, prefix="/api/v1")
app.include_router(intelligence_router, prefix="/api/v1")
app.include_router(passports_router, prefix="/api/v1")
