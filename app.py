import io
import os
import secrets
import string
import time
from threading import Lock

import requests
from captcha.image import ImageCaptcha
from flask import (
    Flask, Response, redirect, render_template_string,
    request, session, url_for
)
from itsdangerous import (
    URLSafeTimedSerializer, BadSignature, SignatureExpired
)

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

LINK_SECRET = os.environ["VERIFY_LINK_SECRET"]
BOT_TOKEN = os.environ["DISCORD_TOKEN"]

GUILD_ID = 1493095298241658961
UNVERIFIED_ROLE_ID = 1493808770495549490
VERIFIED_ROLE_ID = 1493095844352626881

LINK_LIFETIME = 900
CAPTCHA_LIFETIME = 300
MAX_ATTEMPTS = 5

signer = URLSafeTimedSerializer(
    LINK_SECRET,
    salt="heuler-verification-v1"
)

# Challenges are stored server-side, not in browser cookies.
challenges = {}
challenge_lock = Lock()

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Serpent's Recital | Verification</title>
<style>
body {
    background: #101016;
    color: #f2edf2;
    font-family: Georgia, serif;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    margin: 0;
}
.panel {
    background: #1b1923;
    border: 1px solid #68536f;
    border-radius: 12px;
    padding: 35px;
    max-width: 480px;
    width: 88%;
    text-align: center;
}
h1 { color: #dfbde3; }
p { line-height: 1.6; }
img {
    max-width: 100%;
    margin: 15px 0;
    border-radius: 5px;
}
input {
    padding: 12px;
    width: 85%;
    border: 1px solid #68536f;
    border-radius: 5px;
    font-size: 18px;
    text-align: center;
}
button, a.refresh {
    display: inline-block;
    background: #74547e;
    color: white;
    padding: 12px 24px;
    border: 0;
    border-radius: 6px;
    cursor: pointer;
    margin-top: 18px;
    text-decoration: none;
    font-size: 15px;
}
.error { color: #ff9c9c; }
</style>
</head>
<body>
<div class="panel">
    <h1>Serpent's Recital</h1>
    <p>Enter the eight characters shown below
       to complete your verification.</p>

    {% if error %}
    <p class="error">{{ error }}</p>
    {% endif %}

    <img src="{{ url_for('captcha_image') }}"
         alt="Distorted CAPTCHA characters">

    <form method="POST" autocomplete="off">
        <input name="answer" maxlength="8"
               placeholder="Enter characters" required>
        <button type="submit">Continue</button>
    </form>

    <a class="refresh"
       href="{{ url_for('refresh_captcha') }}">
       ↻ New Image
    </a>
</div>
</body>
</html>
"""

RESULT_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Serpent's Recital</title>
<style>
body {
    background: #101016;
    color: #dfbde3;
    font-family: Georgia, serif;
    text-align: center;
    padding: 15vh 20px;
}
p { color: #f2edf2; }
</style>
</head>
<body>
<h1>{{ heading }}</h1>
<p>{{ message }}</p>
</body>
</html>
"""


def result_page(heading, message, status=200):
    return render_template_string(
        RESULT_PAGE,
        heading=heading,
        message=message
    ), status


def get_verified_user():
    token = session.get("verification_token")

    if not token:
        return None

    try:
        data = signer.loads(
            token,
            max_age=LINK_LIFETIME
        )
    except (BadSignature, SignatureExpired):
        return None

    if data.get("guild_id") != GUILD_ID:
        return None

    user_id = data.get("user_id")

    if not isinstance(user_id, int):
        return None

    return user_id


def generate_captcha():
    alphabet = string.ascii_uppercase + string.digits

    answer = "".join(
        secrets.choice(alphabet)
        for _ in range(8)
    )

    challenge_id = secrets.token_urlsafe(24)

    with challenge_lock:
        old_id = session.get("challenge_id")
        challenges.pop(old_id, None)

        # Remove expired challenges.
        now = time.time()
        for key, item in list(challenges.items()):
            if now - item["created"] > CAPTCHA_LIFETIME:
                challenges.pop(key, None)

        challenges[challenge_id] = {
            "answer": answer,
            "created": now,
            "attempts": 0,
            "user_id": get_verified_user()
        }

    session["challenge_id"] = challenge_id


def current_challenge():
    challenge_id = session.get("challenge_id")

    with challenge_lock:
        item = challenges.get(challenge_id)

        if item is None:
            return None

        if time.time() - item["created"] > CAPTCHA_LIFETIME:
            challenges.pop(challenge_id, None)
            return None

        if item["user_id"] != get_verified_user():
            return None

        return dict(item)


def discord_request(method, path, **kwargs):
    return requests.request(
        method,
        "https://discord.com/api/v10" + path,
        headers={
            "Authorization": f"Bot {BOT_TOKEN}"
        },
        timeout=15,
        **kwargs
    )


def assign_verified_roles(user_id):
    base = f"/guilds/{GUILD_ID}/members/{user_id}"

    member_response = discord_request("GET", base)
    member_response.raise_for_status()
    member_data = member_response.json()

    roles = member_data.get("roles", [])

    if str(VERIFIED_ROLE_ID) in roles:
        return True

    # Give Verified before removing Unverified, to avoid
    # leaving a member without either role if Discord fails.
    add_response = discord_request(
        "PUT",
        f"{base}/roles/{VERIFIED_ROLE_ID}"
    )
    add_response.raise_for_status()

    if str(UNVERIFIED_ROLE_ID) in roles:
        remove_response = discord_request(
            "DELETE",
            f"{base}/roles/{UNVERIFIED_ROLE_ID}"
        )
        remove_response.raise_for_status()

    return True


def send_confirmation_dm(user_id):
    try:
        dm_response = discord_request(
            "POST",
            "/users/@me/channels",
            json={"recipient_id": str(user_id)}
        )
        dm_response.raise_for_status()
        channel_id = dm_response.json()["id"]

        discord_request(
            "POST",
            f"/channels/{channel_id}/messages",
            json={
                "content": (
                    "**Wunderbar.** Your verification is complete. "
                    "Welcome to Serpent's Recital."
                )
            }
        )
    except (requests.RequestException, KeyError):
        # Closed DMs should not undo successful verification.
        pass


@app.get("/")
def home():
    token = request.args.get("token")

    if token:
        # A new link starts a fresh verification session.
        session["verification_token"] = token
        session.pop("challenge_id", None)

    if get_verified_user() is None:
        return result_page(
            "Invalid Verification Link",
            "Please return to Heuler's DMs and request a new link.",
            403
        )

    if current_challenge() is None:
        generate_captcha()

    return render_template_string(PAGE, error=None)


@app.get("/captcha.png")
def captcha_image():
    if get_verified_user() is None:
        return "Invalid verification link.", 403

    challenge = current_challenge()

    if challenge is None:
        return "CAPTCHA expired. Refresh the page.", 400

    image = ImageCaptcha(width=350, height=110)
    data = image.generate(challenge["answer"])

    return Response(
        data.getvalue(),
        mimetype="image/png",
        headers={"Cache-Control": "no-store"}
    )


@app.get("/refresh")
def refresh_captcha():
    if get_verified_user() is None:
        return result_page(
            "Link Expired",
            "Please request a new link from Heuler.",
            403
        )

    generate_captcha()
    return redirect(url_for("home"))


@app.post("/")
def verify():
    user_id = get_verified_user()

    if user_id is None:
        return result_page(
            "Link Expired",
            "Please request a new link from Heuler.",
            403
        )

    challenge_id = session.get("challenge_id")
    submitted = request.form.get(
        "answer", ""
    ).strip().upper()

    with challenge_lock:
        challenge = challenges.get(challenge_id)

        if (
            challenge is None
            or time.time() - challenge["created"] > CAPTCHA_LIFETIME
            or challenge["user_id"] != user_id
        ):
            invalid = True
            too_many = False
            correct = False
        else:
            invalid = False
            challenge["attempts"] += 1

            correct = secrets.compare_digest(
                submitted,
                challenge["answer"]
            )

            too_many = challenge["attempts"] >= MAX_ATTEMPTS

            if correct or too_many:
                challenges.pop(challenge_id, None)

    if invalid:
        generate_captcha()
        return render_template_string(
            PAGE,
            error="CAPTCHA expired. Please try the new image."
        ), 400

    if not correct:
        if too_many:
            generate_captcha()
            return render_template_string(
                PAGE,
                error="Too many incorrect attempts. A new image was generated."
            ), 429

        return render_template_string(
            PAGE,
            error="Incorrect characters. Please try again."
        ), 403

    session.pop("challenge_id", None)

    try:
        assign_verified_roles(user_id)
    except requests.RequestException as error:
        app.logger.error("Discord role update failed: %s", error)
        return result_page(
            "Verification Error",
            "The CAPTCHA was correct, but Discord could not update "
            "your roles. Please contact staff.",
            503
        )

    send_confirmation_dm(user_id)

    session.pop("verification_token", None)

    return result_page(
        "Verification Complete",
        "Your Discord roles have been updated. "
        "You may now return to Serpent's Recital."
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080"))
    )
