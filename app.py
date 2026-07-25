import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, redirect, request

app = Flask(__name__)

LINKVERTISE_URL = os.getenv(
    "LINKVERTISE_URL",
    "https://link-hub.net/7774223/AvhFq6Fr49hN"
).strip()

LINKVERTISE_TOKEN = os.getenv("LINKVERTISE_TOKEN", "").strip()

LINKVERTISE_VERIFY_URL = (
    "https://publisher.linkvertise.com/api/v1/anti_bypassing"
)

KEY_TTL_SECONDS = max(
    60,
    int(os.getenv("KEY_TTL_SECONDS", "600"))
)

HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
KEY_PREFIX = "NH1_"


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def signing_secret() -> bytes:
    if len(LINKVERTISE_TOKEN) != 64:
        raise RuntimeError("LINKVERTISE_TOKEN is not configured")

    return hashlib.sha256(
        ("nameless-linkvertise:" + LINKVERTISE_TOKEN).encode("utf-8")
    ).digest()


def create_key() -> tuple[str, int]:
    expires_at = int(time.time()) + KEY_TTL_SECONDS

    payload = {
        "exp": expires_at,
        "nonce": secrets.token_hex(16)
    }

    payload_bytes = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True
    ).encode("utf-8")

    encoded_payload = b64url_encode(payload_bytes)

    signature = hmac.new(
        signing_secret(),
        encoded_payload.encode("ascii"),
        hashlib.sha256
    ).digest()

    key = (
        KEY_PREFIX
        + encoded_payload
        + "."
        + b64url_encode(signature)
    )

    return key, expires_at


def validate_key(key: str) -> tuple[bool, dict]:
    if not isinstance(key, str) or not key.startswith(KEY_PREFIX):
        return False, {"error": "invalid_key"}

    try:
        encoded = key[len(KEY_PREFIX):]
        encoded_payload, encoded_signature = encoded.split(".", 1)

        received_signature = b64url_decode(encoded_signature)

        expected_signature = hmac.new(
            signing_secret(),
            encoded_payload.encode("ascii"),
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(
            received_signature,
            expected_signature
        ):
            return False, {"error": "invalid_signature"}

        payload = json.loads(
            b64url_decode(encoded_payload).decode("utf-8")
        )

        expires_at = int(payload["exp"])
        current_time = int(time.time())

        if expires_at <= current_time:
            return False, {
                "error": "expired",
                "expires_at": expires_at
            }

        return True, {
            "expires_at": expires_at,
            "remaining_seconds": expires_at - current_time
        }

    except Exception:
        return False, {"error": "invalid_key"}


def parse_linkvertise_response(response: requests.Response):
    raw_text = response.text.strip()

    try:
        parsed = response.json()
    except ValueError:
        parsed = raw_text

    if isinstance(parsed, bool):
        return parsed, "verified" if parsed else "hash_not_found"

    if isinstance(parsed, dict):
        candidate = parsed.get("valid")

        if candidate is None:
            candidate = parsed.get("success")

        if candidate is None:
            candidate = parsed.get("data")

        if isinstance(candidate, bool):
            return (
                candidate,
                "verified" if candidate else "hash_not_found"
            )

        if candidate is not None:
            parsed = candidate

    normalized = str(parsed).strip().strip('"').lower()

    if normalized == "true":
        return True, "verified"

    if normalized == "false":
        return False, "hash_not_found"

    if "invalid token" in normalized:
        return False, "invalid_token"

    return False, "unexpected_response"


def verify_linkvertise_hash(hash_value: str):
    if len(LINKVERTISE_TOKEN) != 64:
        return False, "token_not_configured"

    if not HASH_PATTERN.fullmatch(hash_value or ""):
        return False, "invalid_hash_format"

    try:
        response = requests.post(
            LINKVERTISE_VERIFY_URL,
            params={
                "token": LINKVERTISE_TOKEN,
                "hash": hash_value
            },
            headers={
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "Nameless-Linkvertise-Test/1.0"
            },
            timeout=(3, 6)
        )

        if not response.ok:
            app.logger.warning(
                "Linkvertise returned HTTP %s",
                response.status_code
            )
            return False, "linkvertise_http_error"

        return parse_linkvertise_response(response)

    except requests.Timeout:
        return False, "linkvertise_timeout"

    except requests.RequestException as error:
        app.logger.warning(
            "Linkvertise request failed: %s",
            type(error).__name__
        )
        return False, "linkvertise_unavailable"


def render_page(title: str, content: str, status: int = 200):
    safe_title = html.escape(title)

    document = f"""
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta
        name="viewport"
        content="width=device-width,initial-scale=1,maximum-scale=1"
    >
    <title>{safe_title}</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            color: #ffffff;
            background: #050505;
            font-family:
                Inter,
                system-ui,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
        }}

        .card {{
            width: 100%;
            max-width: 520px;
            padding: 28px;
            border: 1px solid #252525;
            border-radius: 18px;
            background: #0b0b0b;
            box-shadow: 0 20px 70px rgba(0, 0, 0, .55);
        }}

        h1 {{
            margin: 0 0 12px;
            font-size: 25px;
            line-height: 1.2;
        }}

        p {{
            margin: 10px 0;
            color: #a8a8a8;
            line-height: 1.55;
        }}

        .button {{
            display: block;
            width: 100%;
            margin-top: 20px;
            padding: 15px 18px;
            border: 0;
            border-radius: 12px;
            color: #000000;
            background: #ffffff;
            font-size: 15px;
            font-weight: 700;
            text-align: center;
            text-decoration: none;
            cursor: pointer;
        }}

        .secondary {{
            color: #ffffff;
            background: #181818;
            border: 1px solid #292929;
        }}

        .key {{
            width: 100%;
            margin-top: 18px;
            padding: 15px;
            overflow-wrap: anywhere;
            border: 1px solid #292929;
            border-radius: 12px;
            color: #ffffff;
            background: #050505;
            font-family: monospace;
            font-size: 13px;
            user-select: all;
        }}

        .status {{
            display: inline-block;
            margin-bottom: 16px;
            padding: 6px 10px;
            border: 1px solid #292929;
            border-radius: 999px;
            color: #cfcfcf;
            background: #111111;
            font-size: 12px;
        }}

        .error {{
            color: #ff7777;
        }}

        .success {{
            color: #77ff9d;
        }}

        small {{
            display: block;
            margin-top: 15px;
            color: #707070;
            line-height: 1.5;
        }}
    </style>
</head>

<body>
    <main class="card">
        {content}
    </main>
</body>
</html>
"""

    return document, status, {
        "Content-Type": "text/html; charset=utf-8"
    }


@app.after_request
def disable_cache(response):
    response.headers["Cache-Control"] = (
        "no-store, no-cache, must-revalidate, max-age=0"
    )
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/")
def index():
    token_configured = len(LINKVERTISE_TOKEN) == 64

    if token_configured:
        status_text = (
            '<span class="status success">Anti-Bypass настроен</span>'
        )
    else:
        status_text = (
            '<span class="status error">'
            'LINKVERTISE_TOKEN не настроен'
            '</span>'
        )

    content = f"""
        {status_text}

        <h1>Linkvertise Test</h1>

        <p>
            Пройди Linkvertise. После подтверждения сервер проверит
            одноразовый hash через Anti-Bypass API и выдаст тестовый ключ.
        </p>

        <a class="button" href="/go">
            Пройти Linkvertise
        </a>

        <small>
            Ключ действует {KEY_TTL_SECONDS // 60} мин.
        </small>
    """

    return render_page("Linkvertise Test", content)


@app.get("/go")
def go_to_linkvertise():
    if not LINKVERTISE_URL.startswith(("https://", "http://")):
        return render_page(
            "Ошибка",
            """
                <span class="status error">Ошибка конфигурации</span>
                <h1>Неверный LINKVERTISE_URL</h1>
                <p>Проверь переменную окружения в Render.</p>
            """,
            500
        )

    return redirect(LINKVERTISE_URL, code=302)


@app.get("/linkvertise/callback")
def linkvertise_callback():
    hash_value = request.args.get("hash", "").strip()

    if not hash_value:
        return render_page(
            "Проверка не пройдена",
            """
                <span class="status error">Hash отсутствует</span>

                <h1>Ссылка открыта напрямую</h1>

                <p>
                    Linkvertise не передал подтверждающий hash.
                    Сначала необходимо пройти рекламный этап.
                </p>

                <a class="button secondary" href="/">
                    Попробовать снова
                </a>
            """,
            403
        )

    verified, reason = verify_linkvertise_hash(hash_value)

    if not verified:
        reason_names = {
            "invalid_hash_format": "Неверный формат hash",
            "hash_not_found": "Hash не найден или уже использован",
            "invalid_token": "Неверный Anti-Bypass Token",
            "token_not_configured": "Token не настроен",
            "linkvertise_timeout": "Linkvertise не ответил вовремя",
            "linkvertise_unavailable": "Linkvertise временно недоступен",
            "linkvertise_http_error": "Ошибка API Linkvertise",
            "unexpected_response": "Неизвестный ответ Linkvertise"
        }

        safe_reason = html.escape(
            reason_names.get(reason, "Проверка не пройдена")
        )

        return render_page(
            "Проверка не пройдена",
            f"""
                <span class="status error">Anti-Bypass отклонил запрос</span>

                <h1>Доступ не подтверждён</h1>

                <p>{safe_reason}.</p>

                <p>
                    Не обновляй callback-страницу: hash одноразовый.
                    Начни прохождение заново.
                </p>

                <a class="button secondary" href="/">
                    Пройти заново
                </a>
            """,
            403
        )

    try:
        key, expires_at = create_key()
    except RuntimeError:
        return render_page(
            "Ошибка сервера",
            """
                <span class="status error">Ошибка конфигурации</span>

                <h1>Ключ не создан</h1>

                <p>На сервере не настроен LINKVERTISE_TOKEN.</p>
            """,
            500
        )

    expires_text = datetime.fromtimestamp(
        expires_at,
        tz=timezone.utc
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    safe_key = html.escape(key)
    safe_expiration = html.escape(expires_text)

    content = f"""
        <span class="status success">Проверка пройдена</span>

        <h1>Ключ получен</h1>

        <p>
            Linkvertise подтвердил прохождение. Ключ действует до
            {safe_expiration}.
        </p>

        <div class="key" id="key">{safe_key}</div>

        <button class="button" onclick="copyKey()">
            Скопировать ключ
        </button>

        <a class="button secondary" href="/">
            На главную
        </a>

        <script>
            async function copyKey() {{
                const key = document
                    .getElementById("key")
                    .textContent
                    .trim();

                try {{
                    await navigator.clipboard.writeText(key);
                    event.target.textContent = "Скопировано";
                }} catch (_) {{
                    const range = document.createRange();
                    range.selectNode(
                        document.getElementById("key")
                    );

                    const selection = window.getSelection();
                    selection.removeAllRanges();
                    selection.addRange(range);

                    document.execCommand("copy");
                    selection.removeAllRanges();

                    event.target.textContent = "Скопировано";
                }}
            }}
        </script>
    """

    return render_page("Ключ получен", content)


@app.route("/api/validate-key", methods=["GET", "POST"])
def api_validate_key():
    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        body = {}

    key = (
        body.get("key")
        or request.form.get("key")
        or request.args.get("key")
        or ""
    )

    valid, result = validate_key(str(key).strip())

    response = {
        "success": valid,
        "valid": valid
    }

    response.update(result)

    return jsonify(response), 200 if valid else 401


@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "linkvertise_url_configured": bool(LINKVERTISE_URL),
        "anti_bypass_token_configured": (
            len(LINKVERTISE_TOKEN) == 64
        )
    })


@app.errorhandler(404)
def not_found(_):
    return render_page(
        "Не найдено",
        """
            <span class="status error">404</span>
            <h1>Страница не найдена</h1>
            <a class="button secondary" href="/">На главную</a>
        """,
        404
    )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "10000"))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
