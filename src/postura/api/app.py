"""FastAPI application entry point — P5.1c"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from postura.config import settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialize Neo4j schema. Shutdown: close driver."""
    logger.info("POSTURA API starting up...")
    try:
        from postura.graph.schema import init_schema
        from postura.graph.connection import health_check
        if health_check():
            init_schema()
            logger.info("Neo4j schema initialized")
        else:
            logger.warning("Neo4j not reachable on startup — schema not initialized")
    except Exception as e:
        logger.error("Startup error: %s", e)
    yield
    from postura.graph.connection import close_driver
    close_driver()
    logger.info("POSTURA API shut down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="POSTURA",
        description="Attack Surface Posture Agent — security graph for your codebase",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS — restrict in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],   # tighten in production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check
    @app.get("/health")
    async def health():
        from postura.graph.connection import health_check
        neo4j_ok = health_check()
        return {
            "status": "ok" if neo4j_ok else "degraded",
            "neo4j": "connected" if neo4j_ok else "unreachable",
        }

    # Mount routers
    from postura.webhook.receiver import router as webhook_router
    from postura.api.routes import router as api_router

    app.include_router(webhook_router)
    app.include_router(api_router)

    return app


app = create_app()
