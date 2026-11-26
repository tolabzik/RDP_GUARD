import json
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

from ..windows.ipc import PipeClient, RemoteError

ORIGIN = "http://127.0.0.1:8787"
COOKIE = "rdpguard_session"
ROOT = Path(__file__).parent


def create_app(client=None, status_path=None):
    client = client or PipeClient()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    templates = Jinja2Templates(directory=str(ROOT / "templates"))
    app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")

    def service_status():
        from ..windows.platform import DATA_DIR
        path = Path(status_path) if status_path else DATA_DIR / "service-status/status.json"
        try:
            if path.stat().st_size > 8192:
                raise ValueError("Oversized status")
            value = json.loads(path.read_text(encoding="utf-8"))
            # Public loopback health contains only numeric SCM status, never detailed history.
            return {"checked_at": float(value["checked_at"]), "services": {
                name: {key: item[key] for key in ("state", "exit_code", "service_exit_code")
                       if type(item.get(key)) is int}
                for name, item in value["services"].items()
                if name in ("RDPGuardService", "RDPGuardWeb")}}
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return {"checked_at": None, "services": {}}

    @app.get("/api/service-status")
    async def local_service_status():
        return service_status()

    @app.middleware("http")
    async def boundaries(request: Request, call_next):
        if not request.client or request.client.host != "127.0.0.1" or request.headers.get("host") != "127.0.0.1:8787":
            return JSONResponse({"error": "Loopback access only"}, status_code=403)
        if request.method not in ("GET", "HEAD"):
            if request.headers.get("origin") != ORIGIN or request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse({"error": "Invalid request origin or content type"}, status_code=403)
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    async def call(request, operation, args=None):
        envelope = {"op": operation, "args": args or {}, "token": request.cookies.get(COOKIE),
                    "csrf": request.headers.get("x-csrf-token")}
        return await run_in_threadpool(client.call, envelope)

    async def body(request):
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > 250000:
                raise ValueError("Request body is too large")
        decoded = json.loads(data)
        if not isinstance(decoded, dict):
            raise ValueError("Expected a JSON object")
        return decoded

    @app.exception_handler(RemoteError)
    async def remote_error(request, exc):
        return JSONResponse({"error": str(exc)}, status_code=exc.code)

    @app.exception_handler(ValueError)
    async def invalid_request(request, exc):
        return JSONResponse({"error": str(exc)}, status_code=400)

    @app.exception_handler(Exception)
    async def service_error(request, exc):
        return JSONResponse({"error": "Служба защиты недоступна. Watchdog повторяет запуск; подробности появятся в журнале службы после восстановления.",
                             "service_status": service_status()}, status_code=503)

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        try:
            user = await call(request, "session")
        except RemoteError as exc:
            if exc.code == 401:
                return RedirectResponse("/login", 303)
            raise
        except Exception:
            return templates.TemplateResponse(request=request, name="unavailable.html", context={}, status_code=503)
        return templates.TemplateResponse(request=request, name="index.html", context={"user": user["username"]})

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        return templates.TemplateResponse(request=request, name="login.html", context={})

    @app.post("/api/login")
    async def login(request: Request):
        data = await body(request)
        result = await call(request, "login", {"username": data.get("username"), "password": data.get("password")})
        response = JSONResponse({"ok": True})
        # HTTP is deliberately limited to numeric loopback; Secure cannot be relied on over HTTP.
        response.set_cookie(COOKIE, result["token"], httponly=True, samesite="strict", secure=False,
                            max_age=28800, path="/")
        return response

    @app.get("/api/session")
    async def session(request: Request):
        return await call(request, "session")

    @app.post("/api/rpc")
    async def rpc(request: Request):
        data = await body(request)
        operation = data.get("op")
        if operation in ("login", "session") or not isinstance(operation, str):
            raise ValueError("Invalid operation")
        result = await call(request, operation, data.get("args", {}))
        response = JSONResponse(result)
        if operation == "logout":
            response.delete_cookie(COOKIE, path="/")
        return response

    return app


def run_web(stop):
    import threading
    import uvicorn
    from ..runtime import configure_logging
    from ..windows.platform import DATA_DIR, require_unprivileged
    require_unprivileged()
    configure_logging(DATA_DIR / "web-logs", "web")
    config = uvicorn.Config(create_app(), host="127.0.0.1", port=8787, workers=1, proxy_headers=False,
                            server_header=False, access_log=False, limit_concurrency=32, backlog=32,
                            timeout_keep_alive=5, log_config=None)
    server = uvicorn.Server(config)
    def shutdown():
        stop.wait()
        server.should_exit = True
    threading.Thread(target=shutdown, daemon=True).start()
    server.run()
