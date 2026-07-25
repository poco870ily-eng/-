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

LINKVERTISE_TOKEN = os.getenv(
    "LINKVERTISE_TOKEN",
    ""
).strip()

LINKVERTISE_VERIFY_URL = (
    "https://publisher.linkvertise.com/api/v1/anti_bypassing"
)

KEY_TTL_SECONDS = max(
    60,
    int(os.getenv("KEY_TTL_SECONDS", "600"))
)

KEY_PREFIX = "NH1_"


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(
        value
    ).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)

    return base64.urlsafe_b64decode(
        value + padding
    )


def get_signing_secret() -> bytes:
    if not LINKVERTISE_TOKEN:
        raise RuntimeError(
            "LINKVERTISE_TOKEN is not configured"
        )

    return hashlib.sha256(
        (
            "nameless-linkvertise:"
            + LINKVERTISE_TOKEN
        ).encode("utf-8")
    ).digest()


def create_key():
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

    encoded_payload = b64url_encode(
        payload_bytes
    )

    signature = hmac.new(
        get_signing_secret(),
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


def validate_key(key: str):
    if not isinstance(key, str):
        return False, {
            "error": "invalid_key"
        }

    if not key.startswith(KEY_PREFIX):
        return False, {
            "error": "invalid_key"
        }

    try:
        encoded_key = key[len(KEY_PREFIX):]

        encoded_payload, encoded_signature = (
            encoded_key.split(".", 1)
        )

        received_signature = b64url_decode(
            encoded_signature
        )

        expected_signature = hmac.new(
            get_signing_secret(),
            encoded_payload.encode("ascii"),
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(
            received_signature,
            expected_signature
        ):
            return False, {
                "error": "invalid_signature"
            }

        payload = json.loads(
            b64url_decode(
                encoded_payload
            ).decode("utf-8")
        )

        expires_at = int(
            payload["exp"]
        )

        current_time = int(
            time.time()
        )

        if expires_at <= current_time:
            return False, {
                "error": "expired",
                "expires_at": expires_at
            }

        return True, {
            "expires_at": expires_at,
            "remaining_seconds": (
                expires_at - current_time
            )
        }

    except Exception:
        return False, {
            "error": "invalid_key"
        }


def normalize_api_text(value) -> str:
    text = str(
        value if value is not None else ""
    )

    text = text.lstrip("\ufeff")
    text = html.unescape(text)

    text = re.sub(
        r"<[^>]+>",
        " ",
        text
    )

    text = text.strip()

    while (
        len(text) >= 2
        and text[0] in "\"'"
        and text[-1] == text[0]
    ):
        text = text[1:-1].strip()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.lower().strip()


def classify_api_value(value, depth=0):
    if depth > 8:
        return None

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        normalized = normalize_api_text(
            value
        )

        if "invalid token" in normalized:
            return "invalid_token"

        if normalized in {
            "true",
            "1",
            "yes",
            "ok",
            "valid",
            "verified",
            "success",
            "successful",
            "approved"
        }:
            return True

        if normalized in {
            "false",
            "0",
            "no",
            "invalid",
            "failed",
            "failure",
            "expired",
            "not found",
            "hash not found"
        }:
            return False

        if (
            "hash was found" in normalized
            or "found and deleted" in normalized
            or "verification successful" in normalized
            or "successfully verified" in normalized
        ):
            return True

        if (
            "hash could not be found" in normalized
            or "hash was not found" in normalized
            or "invalid hash" in normalized
            or "hash expired" in normalized
            or "already used" in normalized
        ):
            return False

        return None

    if isinstance(value, dict):
        priority_fields = (
            "valid",
            "verified",
            "success",
            "successful",
            "approved",
            "result",
            "response",
            "data",
            "value",
            "message"
        )

        for field in priority_fields:
            if field not in value:
                continue

            result = classify_api_value(
                value[field],
                depth + 1
            )

            if result is not None:
                return result

        for nested_value in value.values():
            result = classify_api_value(
                nested_value,
                depth + 1
            )

            if result is not None:
                return result

        return None

    if isinstance(value, (list, tuple)):
        for item in value:
            result = classify_api_value(
                item,
                depth + 1
            )

            if result is not None:
                return result

    return None


def parse_linkvertise_response(
    response: requests.Response
):
    raw_text = response.text.lstrip(
        "\ufeff"
    ).strip()

    content_type = response.headers.get(
        "Content-Type",
        ""
    )

    app.logger.info(
        "Linkvertise response: status=%s content_type=%r body=%r",
        response.status_code,
        content_type,
        raw_text[:1000]
    )

    raw_result = classify_api_value(
        raw_text
    )

    if raw_result is True:
        return True, "verified", None

    if raw_result is False:
        return False, "hash_not_found", None

    if raw_result == "invalid_token":
        return False, "invalid_token", None

    try:
        json_data = response.json()
    except ValueError:
        json_data = None

    if json_data is not None:
        json_result = classify_api_value(
            json_data
        )

        if json_result is True:
            return True, "verified", None

        if json_result is False:
            return False, "hash_not_found", None

        if json_result == "invalid_token":
            return False, "invalid_token", None

    debug_info = {
        "http_status": response.status_code,
        "content_type": content_type[:150],
        "response": raw_text[:1000]
    }

    if "text/html" in content_type.lower():
        return (
            False,
            "linkvertise_html_response",
            debug_info
        )

    return (
        False,
        "unexpected_response",
        debug_info
    )


def verify_linkvertise_hash(hash_value: str):
    if not LINKVERTISE_TOKEN:
        return (
            False,
            "token_not_configured",
            None
        )

    if not isinstance(hash_value, str):
        return (
            False,
            "invalid_hash",
            None
        )

    hash_value = hash_value.strip()

    if not hash_value:
        return (
            False,
            "hash_missing",
            None
        )

    if len(hash_value) > 512:
        return (
            False,
            "invalid_hash",
            None
        )

    app.logger.info(
        "Checking Linkvertise hash: hash_length=%s token_length=%s",
        len(hash_value),
        len(LINKVERTISE_TOKEN)
    )

    parameters = {
        "token": LINKVERTISE_TOKEN,
        "hash": hash_value
    }

    try:
        response = requests.post(
            LINKVERTISE_VERIFY_URL,
            params=parameters,
            data=parameters,
            headers={
                "Accept": (
                    "application/json, "
                    "text/plain, "
                    "text/html, "
                    "*/*"
                ),
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/126.0 Safari/537.36"
                )
            },
            timeout=(4, 10),
            allow_redirects=False
        )

        if 300 <= response.status_code < 400:
            return (
                False,
                "linkvertise_redirect",
                {
                    "http_status": (
                        response.status_code
                    ),
                    "location": (
                        response.headers.get(
                            "Location",
                            ""
                        )[:500]
                    )
                }
            )

        if not response.ok:
            return (
                False,
                "linkvertise_http_error",
                {
                    "http_status": (
                        response.status_code
                    ),
                    "content_type": (
                        response.headers.get(
                            "Content-Type",
                            ""
                        )[:150]
                    ),
                    "response": (
                        response.text[:1000]
                    )
                }
            )

        return parse_linkvertise_response(
            response
        )

    except requests.Timeout:
        return (
            False,
            "linkvertise_timeout",
            None
        )

    except requests.RequestException as error:
        app.logger.exception(
            "Linkvertise request failed"
        )

        return (
            False,
            "linkvertise_unavailable",
            {
                "error": type(error).__name__,
                "message": str(error)[:500]
            }
        )


def render_page(
    title: str,
    content: str,
    status: int = 200
):
    safe_title = html.escape(
        title
    )

    page = f"""
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width,initial-scale=1"
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
            color: #fff;
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
            max-width: 540px;
            padding: 28px;
            border: 1px solid #252525;
            border-radius: 18px;
            background: #0b0b0b;
            box-shadow:
                0 20px 70px
                rgba(0, 0, 0, .55);
        }}

        h1 {{
            margin: 0 0 12px;
            font-size: 25px;
            line-height: 1.2;
        }}

        p {{
            margin: 10px 0;
            color: #aaa;
            line-height: 1.55;
        }}

        .button {{
            display: block;
            width: 100%;
            margin-top: 20px;
            padding: 15px 18px;
            border: 0;
            border-radius: 12px;
            color: #000;
            background: #fff;
            font-size: 15px;
            font-weight: 700;
            text-align: center;
            text-decoration: none;
            cursor: pointer;
        }}

        .button.secondary {{
            color: #fff;
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
            color: #fff;
            background: #050505;
            font-family: monospace;
            font-size: 13px;
            user-select: all;
        }}

        .debug {{
            width: 100%;
            margin-top: 18px;
            padding: 15px;
            overflow: hidden;
            border: 1px solid #392323;
            border-radius: 12px;
            color: #ffb1b1;
            background: #100707;
            font-family: monospace;
            font-size: 12px;
        }}

        .debug pre {{
            margin: 10px 0 0;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            color: #d6a4a4;
        }}

        .status {{
            display: inline-block;
            margin-bottom: 16px;
            padding: 6px 10px;
            border: 1px solid #292929;
            border-radius: 999px;
            color: #cfcfcf;
            background: #111;
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

    return page, status, {
        "Content-Type": "text/html; charset=utf-8"
    }


@app.after_request
def add_headers(response):
    response.headers["Cache-Control"] = (
        "no-store, no-cache, "
        "must-revalidate, max-age=0"
    )

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    return response


@app.get("/")
def index():
    if LINKVERTISE_TOKEN:
        token_status = """
            <span class="status success">
                Anti-Bypass настроен
            </span>
        """
    else:
        token_status = """
            <span class="status error">
                LINKVERTISE_TOKEN не настроен
            </span>
        """

    return render_page(
        "Linkvertise Test",
        f"""
            {token_status}

            <h1>Linkvertise Test</h1>

            <p>
                Пройди Linkvertise. После завершения
                сервер проверит hash и выдаст ключ.
            </p>

            <a class="button" href="/go">
                Пройти Linkvertise
            </a>

            <small>
                Ключ действует
                {KEY_TTL_SECONDS // 60} минут.
            </small>
        """
    )


@app.get("/go")
def go_to_linkvertise():
    if not LINKVERTISE_URL.startswith(
        ("https://", "http://")
    ):
        return render_page(
            "Ошибка",
            """
                <span class="status error">
                    Ошибка конфигурации
                </span>

                <h1>Неверный LINKVERTISE_URL</h1>

                <p>
                    Проверь LINKVERTISE_URL
                    в Environment Variables Render.
                </p>
            """,
            500
        )

    return redirect(
        LINKVERTISE_URL,
        code=302
    )


@app.get("/linkvertise/callback")
def linkvertise_callback():
    hash_value = request.args.get(
        "hash",
        ""
    ).strip()

    if not hash_value:
        return render_page(
            "Проверка не пройдена",
            """
                <span class="status error">
                    Hash отсутствует
                </span>

                <h1>Ссылка открыта напрямую</h1>

                <p>
                    Linkvertise не передал hash.
                    Пройди ссылку заново.
                </p>

                <a class="button secondary" href="/">
                    Вернуться
                </a>
            """,
            403
        )

    verified, reason, debug_info = (
        verify_linkvertise_hash(
            hash_value
        )
    )

    if not verified:
        reason_names = {
            "hash_missing": (
                "Linkvertise не передал hash"
            ),
            "invalid_hash": (
                "Получен некорректный hash"
            ),
            "hash_not_found": (
                "Hash не найден, истёк "
                "или уже был использован"
            ),
            "invalid_token": (
                "Неверный Anti-Bypass Token"
            ),
            "token_not_configured": (
                "LINKVERTISE_TOKEN не настроен"
            ),
            "linkvertise_timeout": (
                "Linkvertise не ответил вовремя"
            ),
            "linkvertise_unavailable": (
                "Не удалось подключиться к Linkvertise"
            ),
            "linkvertise_http_error": (
                "API Linkvertise вернул HTTP-ошибку"
            ),
            "linkvertise_redirect": (
                "API Linkvertise перенаправил запрос"
            ),
            "linkvertise_html_response": (
                "Linkvertise вернул HTML вместо ответа API"
            ),
            "unexpected_response": (
                "Linkvertise вернул нестандартный ответ"
            )
        }

        message = reason_names.get(
            reason,
            "Проверка не пройдена"
        )

        safe_message = html.escape(
            message
        )

        debug_html = ""

        if debug_info:
            safe_debug = html.escape(
                json.dumps(
                    debug_info,
                    ensure_ascii=False,
                    indent=2
                )
            )

            debug_html = f"""
                <div class="debug">
                    Ответ API:
                    <pre>{safe_debug}</pre>
                </div>
            """

        return render_page(
            "Проверка не пройдена",
            f"""
                <span class="status error">
                    Anti-Bypass отклонил запрос
                </span>

                <h1>Доступ не подтверждён</h1>

                <p>{safe_message}.</p>

                {debug_html}

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
                <span class="status error">
                    Ошибка конфигурации
                </span>

                <h1>Ключ не создан</h1>

                <p>
                    LINKVERTISE_TOKEN не настроен.
                </p>
            """,
            500
        )

    expires_text = datetime.fromtimestamp(
        expires_at,
        tz=timezone.utc
    ).strftime(
        "%d.%m.%Y %H:%M:%S UTC"
    )

    safe_key = html.escape(
        key
    )

    safe_expiration = html.escape(
        expires_text
    )

    return render_page(
        "Ключ получен",
        f"""
            <span class="status success">
                Проверка пройдена
            </span>

            <h1>Ключ получен</h1>

            <p>
                Ключ действует до
                {safe_expiration}.
            </p>

            <div class="key" id="key">
                {safe_key}
            </div>

            <button
                class="button"
                onclick="copyKey(this)"
            >
                Скопировать ключ
            </button>

            <a class="button secondary" href="/">
                На главную
            </a>

            <script>
                async function copyKey(button) {{
                    const element =
                        document.getElementById("key");

                    const key =
                        element.textContent.trim();

                    try {{
                        await navigator.clipboard.writeText(
                            key
                        );

                        button.textContent =
                            "Скопировано";
                    }} catch (error) {{
                        const range =
                            document.createRange();

                        range.selectNodeContents(
                            element
                        );

                        const selection =
                            window.getSelection();

                        selection.removeAllRanges();
                        selection.addRange(range);

                        document.execCommand("copy");

                        selection.removeAllRanges();

                        button.textContent =
                            "Скопировано";
                    }}
                }}
            </script>
        """
    )


@app.route(
    "/api/validate-key",
    methods=["GET", "POST"]
)
def api_validate_key():
    body = request.get_json(
        silent=True
    )

    if not isinstance(body, dict):
        body = {}

    key = (
        body.get("key")
        or request.form.get("key")
        or request.args.get("key")
        or ""
    )

    valid, result = validate_key(
        str(key).strip()
    )

    response_data = {
        "success": valid,
        "valid": valid
    }

    response_data.update(
        result
    )

    return jsonify(
        response_data
    ), 200 if valid else 401


@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "linkvertise_url_configured": bool(
            LINKVERTISE_URL
        ),
        "anti_bypass_token_configured": bool(
            LINKVERTISE_TOKEN
        ),
        "anti_bypass_token_length": len(
            LINKVERTISE_TOKEN
        )
    })


@app.errorhandler(404)
def not_found(_error):
    return render_page(
        "Не найдено",
        """
            <span class="status error">
                404
            </span>

            <h1>Страница не найдена</h1>

            <a class="button secondary" href="/">
                На главную
            </a>
        """,
        404
    )


if __name__ == "__main__":
    port = int(
        os.getenv("PORT", "10000")
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
