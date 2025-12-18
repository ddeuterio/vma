from __future__ import annotations
from typing import Any

import logging
from loguru import logger
from pathlib import Path
from httpx import AsyncClient
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import vma.helper as helper
import vma.auth as a
from vma.api.routers import v1 as api_v1
from vma.api.models import v1 as mod_v1

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def _render_page(
    request: Request, template_name: str, context: dict, tokens: dict
) -> Any:
    headers = None  # TODO: set security headers
    context.update({"request": request})
    if "access_token" in tokens:
        context.update({"access_token": tokens["access_token"]})
    res = templates.TemplateResponse(
        request=request, name=template_name, context=context
    )
    res.status_code = status.HTTP_200_OK
    return res


def create_web_app():
    """
    Build the ASGI application that serves both the SPA and the API.
    """
    app = FastAPI(title="VMA Web")
    helper.configure_logging(logging.DEBUG, uvicorn=True)

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    app.include_router(api_v1.router)

    @app.post("/")
    async def login_post(
        request: Request,
        user_data: mod_v1.JwtData | None = Depends(a.is_authenticated),
    ) -> Any:
        tokens = {}
        ret = None
        try:
            if user_data:
                return _render_page(
                    request=request, template_name="index.html", context={}, tokens={}
                )

            form = await request.form()

            if not form["username"] or not form["password"]:
                context = {"error": "User must provide valid credentials"}
                return _render_page(
                    request=request,
                    template_name="login.html",
                    context=context,
                    tokens={},
                )

            token_endp = request.app.url_path_for("token")
            payload = {"username": form["username"], "password": form["password"]}

            async with AsyncClient(base_url=str(request.base_url)) as client:
                res = await client.post(token_endp, data=payload)

            if res.status_code != status.HTTP_200_OK:
                context = {"error": "Invalid credentials"}
                return _render_page(
                    request=request,
                    template_name="login.html",
                    context=context,
                    tokens={},
                )

            tokens = {"access_token": res.json()["access_token"]}
            ret = _render_page(
                request=request, template_name="index.html", context={}, tokens=tokens
            )

            if res.cookies.get("refresh_token"):
                # TODO: centralize cookie settings
                ret.set_cookie(
                    key="refresh_token",
                    value=res.cookies.get("refresh_token"),
                    httponly=True,
                    secure=True,
                    samesite="lax",
                    max_age=a._expire_refresh_token * 24 * 60 * 60,
                    path="/refresh",
                )
        except Exception as e:
            logger.error(f"Error processing post request: {e}")
            ret = _render_page(
                request=request,
                template_name="login.html",
                context={"error": "User could not be validated"},
                tokens={},
            )
        return ret

    @app.get("/")
    async def index(
        request: Request, user_data: mod_v1.JwtData | None = Depends(a.is_authenticated)
    ) -> Any:
        if user_data is None:
            logger.debug("User is not authenticated, render login page")
            return _render_page(
                request=request, template_name="login.html", context={}, tokens={}
            )
        return _render_page(
            request=request, template_name="index.html", context={}, tokens={}
        )

    @app.get("/{full_path:path}")
    async def spa_fallback(
        request: Request,
        full_path: str,
        user_data: mod_v1.JwtData | None = Depends(a.is_authenticated),
    ) -> Any:
        if (
            full_path.startswith("api/")
            or full_path.startswith("static/")
            or full_path == "favicon.ico"
        ):
            raise HTTPException(status_code=404)

        if user_data is None:
            logger.debug(f"Unauthenticated access to {full_path}, redirecting to login")
            return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)

        return templates.TemplateResponse("index.html", {"request": request})

    return app


app = create_web_app()
