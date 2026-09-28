"""API-key auth with two roles.

analyst - can create, read and update incidents
admin   - everything an analyst can do, plus delete and read the audit log
"""

import hmac

from fastapi import Depends, HTTPException, Request, status


def resolve_role(api_key: str | None, settings) -> str | None:
    if not api_key:
        return None
    # compare_digest avoids leaking key contents through timing
    if hmac.compare_digest(api_key, settings.admin_api_key):
        return "admin"
    if hmac.compare_digest(api_key, settings.analyst_api_key):
        return "analyst"
    return None


def current_role(request: Request) -> str:
    settings = request.app.state.settings
    role = resolve_role(request.headers.get("X-API-Key"), settings)
    if role is None:
        # the 401 is picked up by the middleware, which watches for brute forcing
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid API key")
    return role


def require_admin(role: str = Depends(current_role)) -> str:
    if role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin role required")
    return role
