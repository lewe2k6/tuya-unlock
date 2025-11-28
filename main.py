import os
import time
import hmac
import json
import hashlib
from typing import Optional, Tuple

import requests
from flask import Flask, request, jsonify
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# === CONFIG FROM ENV ===
TUYA_CLIENT_ID = os.getenv("TUYA_CLIENT_ID")
TUYA_CLIENT_SECRET = os.getenv("TUYA_CLIENT_SECRET")
TUYA_BASE_URL = os.getenv("TUYA_BASE_URL", "https://openapi-sg.iotbing.com").rstrip("/")
TUYA_DEVICE_ID = os.getenv("TUYA_DEVICE_ID")
TUYA_UNLOCK_CODE = os.getenv("TUYA_UNLOCK_CODE", "unlock")
API_SHARED_KEY = os.getenv("API_SHARED_KEY")

# DRY RUN: if true, nothing is sent to Tuya, we just simulate success
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1", "true", "yes")

if not all([TUYA_CLIENT_ID, TUYA_CLIENT_SECRET, TUYA_BASE_URL, TUYA_DEVICE_ID, API_SHARED_KEY]):
    raise RuntimeError("Missing required env vars. Check your .env file or environment variables.")

# Constant SHA256 of empty string (Tuya docs)
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Token cache (in-memory)
_cached_access_token: Optional[str] = None
_cached_token_expire_at_ms: int = 0  # epoch ms when token expires (approx)

app = Flask(__name__)


# === UTILS ===

def _now_ms() -> int:
    return int(time.time() * 1000)


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _build_string_to_sign(method: str, path_with_query: str, body_str: str) -> str:
    """
    Build stringToSign per Tuya docs:
        stringToSign = HTTPMethod + "\n" +
                       Content-SHA256 + "\n" +
                       HeadersPart(optional, we leave empty) + "\n" +
                       URL (path + query)
    """
    method = method.upper()
    if body_str:
        content_sha256 = _sha256_hex(body_str)
    else:
        content_sha256 = EMPTY_BODY_SHA256

    # We are not including extra signed headers -> empty line for that part.
    string_to_sign = f"{method}\n{content_sha256}\n\n{path_with_query}"
    return string_to_sign


def _sign_for_token(method: str, path_with_query: str, body_str: str, t_ms: int) -> str:
    """
    Token management signature:
      sign = HMAC-SHA256(client_id + t + stringToSign, secret).toUpperCase()
    """
    string_to_sign = _build_string_to_sign(method, path_with_query, body_str)
    sign_str = f"{TUYA_CLIENT_ID}{t_ms}{string_to_sign}"
    digest = hmac.new(
        TUYA_CLIENT_SECRET.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()
    return digest


def _sign_for_business(method: str, path_with_query: str, body_str: str,
                       t_ms: int, access_token: str) -> str:
    """
    Business API signature:
      sign = HMAC-SHA256(client_id + access_token + t + stringToSign, secret).toUpperCase()
    """
    string_to_sign = _build_string_to_sign(method, path_with_query, body_str)
    sign_str = f"{TUYA_CLIENT_ID}{access_token}{t_ms}{string_to_sign}"
    digest = hmac.new(
        TUYA_CLIENT_SECRET.encode("utf-8"),
        sign_str.encode("utf-8"),
        hashlib.sha256
    ).hexdigest().upper()
    return digest


def _get_access_token() -> str:
    """
    Return a valid access token, refreshing if needed.
    Caches token in memory and reuses until near expiry.
    """
    global _cached_access_token, _cached_token_expire_at_ms

    now = _now_ms()
    # Reuse token if it's still valid for > 60 seconds
    if _cached_access_token and now + 60_000 < _cached_token_expire_at_ms:
        return _cached_access_token

    # Need new token
    method = "GET"
    path_with_query = "/v1.0/token?grant_type=1"
    body_str = ""

    t_ms = _now_ms()
    sign = _sign_for_token(method, path_with_query, body_str, t_ms)

    headers = {
        "client_id": TUYA_CLIENT_ID,
        "sign": sign,
        "t": str(t_ms),
        "sign_method": "HMAC-SHA256",
        "Content-Type": "application/json",
    }

    url = f"{TUYA_BASE_URL}{path_with_query}"
    resp = requests.get(url, headers=headers, timeout=10)

    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError(f"Non-JSON token response: {resp.status_code} {resp.text}")

    if not data.get("success"):
        raise RuntimeError(f"Failed to get Tuya token: {data}")

    result = data.get("result", {})
    access_token = result.get("access_token")
    expire_time = result.get("expire_time")  # in seconds

    if not access_token or not expire_time:
        raise RuntimeError(f"Invalid token response: {data}")

    _cached_access_token = access_token
    _cached_token_expire_at_ms = _now_ms() + int(expire_time) * 1000
    return access_token


def _tuya_post(path: str, payload: dict) -> dict:
    """
    Generic helper for Tuya POST business API.
    """
    access_token = _get_access_token()

    method = "POST"
    path_with_query = path  # no extra query params here
    body_str = json.dumps(payload, separators=(",", ":"))

    t_ms = _now_ms()
    sign = _sign_for_business(method, path_with_query, body_str, t_ms, access_token)

    headers = {
        "client_id": TUYA_CLIENT_ID,
        "access_token": access_token,
        "sign": sign,
        "t": str(t_ms),
        "sign_method": "HMAC-SHA256",
        "Content-Type": "application/json",
    }

    url = f"{TUYA_BASE_URL}{path}"
    resp = requests.post(url, headers=headers, data=body_str, timeout=10)

    try:
        data = resp.json()
    except ValueError:
        raise RuntimeError(f"Non-JSON response from Tuya: {resp.status_code} {resp.text}")

    return data


def _unlock_lock() -> Tuple[bool, dict]:
    """
    Remote unlock for mk lock using Smart Lock APIs.

    Flow:
      1) POST /v1.0/devices/{device_id}/door-lock/password-ticket
         -> get ticket_id
      2) POST /v1.0/devices/{device_id}/door-lock/password-free/open-door
         with { "ticket_id": ticket_id }
    """

    # DRY RUN: don't touch Tuya at all
    if DRY_RUN:
        fake = {
            "step": "dry_run",
            "message": "Would call password-ticket + password-free/open-door here.",
            "paths": {
                "ticket": f"/v1.0/devices/{TUYA_DEVICE_ID}/door-lock/password-ticket",
                "open": f"/v1.0/devices/{TUYA_DEVICE_ID}/door-lock/password-free/open-door"
            }
        }
        return True, fake

    # --- STEP 1: get temporary ticket ---
    ticket_path = f"/v1.0/devices/{TUYA_DEVICE_ID}/door-lock/password-ticket"
    ticket_resp = _tuya_post(ticket_path, {})  # empty JSON body

    if not ticket_resp.get("success"):
        # bubble up ticket error
        return False, {
            "step": "password-ticket",
            "response": ticket_resp
        }

    ticket_result = ticket_resp.get("result") or {}
    ticket_id = ticket_result.get("ticket_id")

    if not ticket_id:
        return False, {
            "step": "password-ticket",
            "error": "No ticket_id in response",
            "response": ticket_resp
        }

    # --- STEP 2: use ticket for password-free unlock ---
    open_path = f"/v1.0/devices/{TUYA_DEVICE_ID}/door-lock/password-free/open-door"
    open_payload = {
        "ticket_id": ticket_id
        # nothing else needed for mk access control
    }
    open_resp = _tuya_post(open_path, open_payload)

    success = bool(open_resp.get("success"))

    # return both steps for debugging
    combined = {
        "step": "password-free-open-door",
        "ticket_resp": ticket_resp,
        "open_resp": open_resp
    }
    return success, combined


# === FLASK ROUTES ===

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "status": "up",
        "dry_run": DRY_RUN
    })


@app.route("/unlock", methods=["POST"])
def unlock():
    # Simple shared-key auth for Siri Shortcut
    api_key = request.headers.get("X-API-Key")
    if not api_key or api_key != API_SHARED_KEY:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    try:
        success, data = _unlock_lock()
        status_code = 200 if success else 500
        return jsonify({
            "ok": success,
            "dry_run": DRY_RUN,
            "tuya_response": data
        }), status_code
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "dry_run": DRY_RUN}), 500

@app.route("/functions", methods=["GET"])
def functions():
    try:
        access_token = _get_access_token()

        method = "GET"
        path = f"/v1.0/devices/{TUYA_DEVICE_ID}/functions"
        path_with_query = path
        body_str = ""

        t_ms = _now_ms()
        sign = _sign_for_business(method, path_with_query, body_str, t_ms, access_token)

        headers = {
            "client_id": TUYA_CLIENT_ID,
            "access_token": access_token,
            "sign": sign,
            "t": str(t_ms),
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json"
        }

        url = f"{TUYA_BASE_URL}{path}"
        resp = requests.get(url, headers=headers)
        return jsonify(resp.json()), 200

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)
