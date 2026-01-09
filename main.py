import os
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse

app = FastAPI()

GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"

def env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/auth")
def auth(request: Request):
    """
    Decap opens a popup to: {base_url}/auth
    We redirect the popup to GitHub's authorize URL.
    """
    client_id = env("GITHUB_CLIENT_ID")

    # Where GitHub should redirect back to (your Render service)
    callback_url = env("OAUTH_CALLBACK_URL")  # e.g. https://your-service.onrender.com/callback

    # Optional: private repos need 'repo' scope.
    scope = os.getenv("GITHUB_SCOPE", "repo")  # set to "repo" if repo is private

    # CSRF protection / flow correlation.
    # Decap doesn't require a specific state value; it just needs the token in the end.
    state = secrets.token_hex(16)

    params = {
        "client_id": client_id,
        "redirect_uri": callback_url,
        "scope": scope,
        "state": state,
        # "allow_signup": "true",  # optional
    }

    return RedirectResponse(f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}", status_code=302)

@app.get("/callback")
async def callback(request: Request):
    code = request.query_params.get("code")
    if not code:
        return PlainTextResponse("Missing ?code", status_code=400)

    async with httpx.AsyncClient() as client:
        r = await client.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": env("GITHUB_CLIENT_ID"),
                "client_secret": env("GITHUB_CLIENT_SECRET"),
                "code": code,
            },
        )
        r.raise_for_status()
        data = r.json()

    token = data.get("access_token")
    if not token:
        return PlainTextResponse("No token", status_code=400)

    # 🔥 Redirect to SAME-ORIGIN callback page
    redirect_url = f"https://avishek-018.github.io/admin/callback.html#token={token}"


    return RedirectResponse(redirect_url, status_code=302)
