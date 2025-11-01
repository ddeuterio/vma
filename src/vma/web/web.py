from __future__ import annotations

from loguru import logger
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import vma.helper as helper
from vma.api.routers import v1 as api_v1

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def create_web_app():
    """
    Build the ASGI application that serves both the SPA and the API.
    """
    app = FastAPI(title="VMA Web")
    helper.configure_logging('DEBUG', uvicorn=True)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(api_v1.router)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse("index.html", {"request": request})

    @app.get("/{full_path:path}", response_class=HTMLResponse)
    async def spa_fallback(request: Request, full_path: str) -> HTMLResponse:
        if (
            full_path.startswith("api/")
            or full_path.startswith("static/")
            or full_path == "favicon.ico"
        ):
            raise HTTPException(status_code=404)
        return templates.TemplateResponse("index.html", {"request": request})

    return app


app = create_web_app()