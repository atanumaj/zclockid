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

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from api.core.config import (
    APP_NAME,
    APP_VERSION,
    WEB_DIR
)
from api.db.init_db import init_db
from api.services.radius_service import sync_freeradius_policies
from api.services.security_service import get_client_ip, is_ip_allowed, get_security_settings

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
    security
)

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Enterprise Active Directory & Network Identity Management Appliance REST API",
    docs_url="/docs",
    redoc_url="/redoc"
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

# Mount Web GUI static files if available
if WEB_DIR.exists() and (WEB_DIR / "index.html").exists():
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="static_web")

# Background thread for periodic RADIUS / AD synchronization
def background_radius_drs_poller():
    while True:
        try:
            time.sleep(60)
            sync_freeradius_policies()
        except Exception:
            pass

@app.on_event("startup")
def on_startup():
    init_db()
    poller = threading.Thread(target=background_radius_drs_poller, daemon=True)
    poller.start()
