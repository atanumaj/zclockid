"""
ZclockID Enterprise Management Appliance - Modular FastAPI Core Application
Consolidates all Active Directory, RADIUS, DNS, NTP, and System Lifecycle modules.
"""

import os
import sys
import time
import threading
from pathlib import Path

# Bootstrap search paths so both 'api.*' and local imports resolve cleanly
_BASE_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _BASE_DIR.parent
for _p in [str(_ROOT_DIR), str(_BASE_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

import sqlite3
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.core.config import (
    APP_NAME,
    APP_VERSION,
    WEB_DIR,
    DATA_DIR,
    DB_PATH
)
from api.db.init_db import init_db
from api.services.radius_service import sync_freeradius_policies
from api.services.security_service import get_client_ip, is_ip_allowed, get_security_settings
from api.services.log_retention_service import prune_logs_by_policy

# Subsystem API Routers
from api.routers import (
    auth,
    system,
    domain,
    users,
    radius,
    registration,
    dns,
    sysvol,
    azure,
    ntp,
    rbac,
    api_keys,
    certificates,
    syslog,
    security,
    federation,
    license,
    self_service
)

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Enterprise Active Directory & Network Identity Management Appliance REST API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

# Global CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Network Subnet CIDR Access Control Middleware
@app.middleware("http")
async def enforce_allowed_subnets(request: Request, call_next):
    # Only enforce on API paths, exempt setup/status, docs, openapi
    path = request.url.path
    if path.startswith("/api/v1/") and not path.startswith("/api/v1/setup/status"):
        client_ip = get_client_ip(request)
        try:
            settings = get_security_settings()
            allowed = settings.get("allowed_subnets_gui", "0.0.0.0/0, ::/0")
            if not is_ip_allowed(client_ip, allowed):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": f"Access Denied: Your IP ({client_ip}) is not permitted by the appliance network security policy."
                    }
                )
        except Exception:
            pass
    return await call_next(request)

# Strict HTTP No-Cache Middleware for API responses
@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Register Subsystem Routers
app.include_router(auth.router)
app.include_router(system.router)
app.include_router(domain.router)
app.include_router(users.router)
app.include_router(radius.router)
app.include_router(registration.router)
app.include_router(dns.router)
app.include_router(sysvol.router)
app.include_router(azure.router)
app.include_router(ntp.router)
app.include_router(rbac.router)
app.include_router(api_keys.router)
app.include_router(certificates.router)
app.include_router(syslog.router)
app.include_router(security.router)
app.include_router(federation.router)
app.include_router(license.router)
app.include_router(self_service.router)

def _serve_portal_html(table_name: str, filename: str):
    """Serves custom uploaded portal HTML from DATA_DIR/portals if enabled, else built-in WEB_DIR page."""
    use_custom = False
    custom_file = DATA_DIR / "portals" / filename
    try:
        if custom_file.exists() and custom_file.is_file():
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute(f"SELECT use_custom_html FROM {table_name} WHERE id = 1")
            row = cur.fetchone()
            conn.close()
            if row and row[0]:
                use_custom = True
    except Exception:
        use_custom = False

    target = custom_file if use_custom else (WEB_DIR / filename)
    if not target.exists():
        raise HTTPException(status_code=404, detail=f"Portal template '{filename}' not found.")

    headers = {
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "same-origin",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": (
            "sandbox allow-forms allow-scripts" if use_custom else
            "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        )
    }

    return FileResponse(
        path=str(target),
        media_type="text/html",
        headers=headers
    )

@app.get("/register.html")
def serve_registration_portal():
    return _serve_portal_html("self_registration_settings", "register.html")

@app.get("/password-reset.html")
def serve_password_reset_portal():
    return _serve_portal_html("self_service_password_settings", "password-reset.html")

@app.get("/portal-assets/{filename}")
def serve_portal_asset(filename: str):
    assets_dir = (DATA_DIR / "portals" / "assets").resolve()
    safe_name = Path(filename).name
    target = (assets_dir / safe_name).resolve()
    if target.parent != assets_dir or not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Portal asset not found.")
    return FileResponse(path=str(target))

# Mount Web GUI static files if available
if WEB_DIR.exists() and (WEB_DIR / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="static_web")

# Background thread for periodic RADIUS / AD synchronization and log retention pruning
def background_radius_drs_poller():
    last_prune = 0.0
    while True:
        try:
            time.sleep(60)
            sync_freeradius_policies()
            now = time.time()
            if now - last_prune >= 3600:
                prune_logs_by_policy(force=False)
                last_prune = now
        except Exception:
            pass

@app.on_event("startup")
def on_startup():
    init_db()
    poller = threading.Thread(target=background_radius_drs_poller, daemon=True)
    poller.start()
