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
    """
    GitHub redirects here with ?code=...&state=...
    We exchange code -> access_token, then postMessage it back to Decap (opener window).
    """
    code = request.query_params.get("code")
    if not code:
        return PlainTextResponse("Missing ?code from GitHub.", status_code=400)

    client_id = env("GITHUB_CLIENT_ID")
    client_secret = env("GITHUB_CLIENT_SECRET")

    # The origin of your Decap site (must match where /admin is served from)
    # Example: https://yourname.github.io or https://yourcustomdomain.com
    site_origin = env("SITE_ORIGIN").rstrip("/")

    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
            },
        )
        r.raise_for_status()
        data = r.json()

    token = data.get("access_token")
    if not token:
        return PlainTextResponse(f"No access_token returned. Response: {data}", status_code=400)

    # This format is what Decap/Netlify CMS expects: "authorization:<provider>:success:<json>"
    # (provider should match backend name 'github')
    payload = {
        "token": token,
        "provider": "github",
    }

    html = f"""
<!doctype html>
<html>
  <head><meta charset="utf-8" /></head>
  <body>
    <p>Authorized. You can close this window.</p>
    <script>
      (function() {{
        var msg = 'authorization:github:success:' + JSON.stringify({payload});
        if (window.opener) {{
          window.opener.postMessage(msg, '{site_origin}');
        }}
        window.close();
      }})();
    </script>
  </body>
</html>
"""
    return HTMLResponse(html)
