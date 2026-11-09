"""Isolated test: verifies the global Exception handler used in main.py
still preserves HTTPException's JSON response and returns JSON for 500s."""
import traceback
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

app = FastAPI()

# Same pattern as main.py
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    traceback.print_exc()
    return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})

@app.post("/auth")
async def auth(request: Request):
    body = await request.json()
    if body.get("boom") == "http":
        raise HTTPException(status_code=401, detail="Invalid Credentials ❌")
    raise RuntimeError("firebase went boom")  # simulates the unhandled Firestore error

# Production mode: uvicorn runs with raise_server_exceptions=False,
# so the client receives the handler's response.
client = TestClient(app, raise_server_exceptions=False)

# 1. HTTPException must still return its proper JSON detail (not be swallowed by the Exception handler)
r = client.post("/auth", json={"boom": "http"})
assert r.status_code == 401, f"expected 401, got {r.status_code}"
assert r.json() == {"detail": "Invalid Credentials ❌"}, r.text
print("PASS: HTTPException -> 401 JSON", r.json())

# 2. Unhandled exception must now return JSON 500 (was plain-text before)
r = client.post("/auth", json={"boom": "other"})
assert r.status_code == 500, f"expected 500, got {r.status_code}"
assert r.json() == {"detail": "Internal Server Error"}, r.text
print("PASS: unhandled -> 500 JSON (production mode)", r.json())

print("ALL TESTS PASSED")
