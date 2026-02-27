"""
main.py — FastAPI application
==============================

Routes:
  GET  /                      → Paste form
  POST /                      → Create session, redirect to /{sid}
  GET  /{sid}                 → Auth form (or session view if cookie valid)
  POST /{sid}/auth            → Verify password, set session cookie
  POST /{sid}/add             → Add item to existing authenticated session
  GET  /{sid}/items           → JSON: fetch all decrypted items (AJAX)
  POST /{sid}/wipe            → Delete session immediately
  GET  /{sid}/stream          → SSE: real-time push notifications

Cookie design:
  clip_auth_{sid}  — httponly, secure: proves authentication (value="1")
  clip_pwd_{sid}   — httponly, secure: stores password server-side so JS
                     never needs to know it. Empty string if no password.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import (
    FastAPI,
    Form,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import session as sess
import security as sec
from config import SESSION_TTL_SECONDS, DEBUG, APP_VERSION


# ---------------------------------------------------------------------------
# App lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await sess.close_redis()


app = FastAPI(lifespan=lifespan, docs_url="/docs" if DEBUG else None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
templates.env.globals["app_version"] = APP_VERSION


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------

def _auth_cookie(sid: str) -> str:
    return f"clip_auth_{sid}"

def _pwd_cookie(sid: str) -> str:
    return f"clip_pwd_{sid}"


def _set_session_cookies(response: Response, sid: str, password: str) -> None:
    """Set both auth and password cookies — both httponly, secure."""
    common = dict(max_age=SESSION_TTL_SECONDS, httponly=True, secure=True, samesite="strict")
    response.set_cookie(key=_auth_cookie(sid), value="1", **common)
    response.set_cookie(key=_pwd_cookie(sid),  value=password, **common)


def _clear_session_cookies(response: Response, sid: str) -> None:
    response.delete_cookie(key=_auth_cookie(sid))
    response.delete_cookie(key=_pwd_cookie(sid))


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


async def _is_authenticated(request: Request, sid: str) -> bool:
    cookie_val = request.cookies.get(_auth_cookie(sid))
    return cookie_val == "1" and await sess.session_exists(sid)


def _get_password(request: Request, sid: str) -> str:
    """Read the stored password from the httponly cookie."""
    return request.cookies.get(_pwd_cookie(sid), "")


# ---------------------------------------------------------------------------
# GET / — Paste form
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ---------------------------------------------------------------------------
# POST / — Create session
# ---------------------------------------------------------------------------

@app.post("/")
async def create_session(
    request: Request,
    text: Annotated[str, Form()],
    password: Annotated[str, Form()] = "",
    secure_mode: Annotated[bool, Form()] = False,
):
    ip = get_client_ip(request)

    banned, ban_type = await sec.is_banned(ip)
    if banned:
        raise HTTPException(status_code=429, detail=f"IP {ban_type}-banned.")

    text = text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Text cannot be empty.")
    if len(text) > 500_000:
        raise HTTPException(status_code=413, detail="Text too large (max 500 KB).")
    if len(password) > 50:
        raise HTTPException(status_code=422, detail="Password too long (max 50 chars).")

    sid = await sess.create_session(
        first_item=text,
        password=password,
        secure_mode=secure_mode,
    )

    response = RedirectResponse(url=f"/{sid}", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookies(response, sid, password)
    return response


# ---------------------------------------------------------------------------
# GET /{sid} — Session page
# ---------------------------------------------------------------------------

@app.get("/{sid}", response_class=HTMLResponse)
async def session_page(request: Request, sid: str):
    if await sess.session_is_locked(sid):
        return templates.TemplateResponse(
            "locked.html", {"request": request, "sid": sid}, status_code=410
        )

    if not await sess.session_exists(sid):
        return templates.TemplateResponse(
            "not_found.html", {"request": request, "sid": sid}, status_code=404
        )

    if await _is_authenticated(request, sid):
        return templates.TemplateResponse(
            "session.html",
            {"request": request, "sid": sid, "ttl": SESSION_TTL_SECONDS},
        )

    return templates.TemplateResponse("auth.html", {"request": request, "sid": sid})


# ---------------------------------------------------------------------------
# POST /{sid}/auth — Authenticate
# ---------------------------------------------------------------------------

@app.post("/{sid}/auth")
async def authenticate(
    request: Request,
    sid: str,
    password: Annotated[str, Form()] = "",
):
    ip = get_client_ip(request)

    banned, ban_type = await sec.is_banned(ip)
    if banned:
        raise HTTPException(status_code=429, detail=f"IP {ban_type}-banned.")

    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")

    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session not found.")

    ok = await sess.verify_password(sid, password)

    if not ok:
        if await sess.session_is_locked(sid):
            return JSONResponse(
                {"error": "session_locked"},
                status_code=410,
            )
        banned_now, ban_type = await sec.check_and_record_attempt(ip)
        remaining = await sec.get_attempts_remaining(ip)
        if banned_now:
            return JSONResponse({"error": "ip_banned", "ban_type": ban_type}, status_code=429)
        return JSONResponse({"error": "wrong_password", "attempts_remaining": remaining}, status_code=401)

    await sec.record_success(ip)
    response = RedirectResponse(url=f"/{sid}", status_code=status.HTTP_303_SEE_OTHER)
    _set_session_cookies(response, sid, password)
    return response


# ---------------------------------------------------------------------------
# GET /{sid}/items — Fetch decrypted items (authenticated, password from cookie)
# ---------------------------------------------------------------------------

@app.get("/{sid}/items")
async def get_items(request: Request, sid: str):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    password = _get_password(request, sid)
    items = await sess.get_items(sid, password)
    return JSONResponse({"items": items})


# ---------------------------------------------------------------------------
# POST /{sid}/add — Add item (password from cookie)
# ---------------------------------------------------------------------------

@app.post("/{sid}/add")
async def add_item(
    request: Request,
    sid: str,
    text: Annotated[str, Form()],
):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")
    if await sess.session_is_locked(sid):
        raise HTTPException(status_code=410, detail="Session locked.")
    if not await sess.session_exists(sid):
        raise HTTPException(status_code=404, detail="Session expired.")

    text = text.strip()
    if not text:
        raise HTTPException(status_code=422, detail="Text cannot be empty.")
    if len(text) > 500_000:
        raise HTTPException(status_code=413, detail="Text too large.")

    password = _get_password(request, sid)
    await sess.add_item(sid, text, password)
    return JSONResponse({"ok": True})


# ---------------------------------------------------------------------------
# POST /{sid}/wipe — Delete session immediately (authenticated)
# ---------------------------------------------------------------------------

@app.post("/{sid}/wipe")
async def wipe_session(request: Request, sid: str):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")

    await sess.delete_session(sid, wiped=True)
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    _clear_session_cookies(response, sid)
    return response


# ---------------------------------------------------------------------------
# GET /{sid}/stream — Server-Sent Events (live push, authenticated)
# ---------------------------------------------------------------------------

HEARTBEAT_INTERVAL = 25

@app.get("/{sid}/stream")
async def sse_stream(request: Request, sid: str):
    if not await _is_authenticated(request, sid):
        raise HTTPException(status_code=401, detail="Not authenticated.")

    async def event_generator():
        yield "data: connected\n\n"

        subscriber = sess.subscribe_to_session(sid)
        queue: asyncio.Queue = asyncio.Queue()

        async def _listen():
            async for event in subscriber:
                await queue.put(event)
            await queue.put(None)

        listener_task = asyncio.create_task(_listen())

        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=HEARTBEAT_INTERVAL)
                except asyncio.TimeoutError:
                    if not await sess.session_exists(sid):
                        yield "data: session_expired\n\n"
                        break
                    if await sess.session_is_locked(sid):
                        yield "data: session_locked\n\n"
                        break
                    yield "data: heartbeat\n\n"
                    continue

                if event is None:
                    break

                yield f"data: {event}\n\n"

                if event in ("session_expired", "session_locked", "session_wiped"):
                    break

                if await request.is_disconnected():
                    break

        finally:
            listener_task.cancel()
            try:
                await listener_task
            except asyncio.CancelledError:
                pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
