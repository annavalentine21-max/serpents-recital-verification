import io
import os
import secrets
import string
import time

from captcha.image import ImageCaptcha
from flask import Flask, Response, redirect, render_template_string, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

CAPTCHA_LENGTH = 8
CAPTCHA_LIFETIME = 300
MAX_ATTEMPTS = 5

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
            justify-content: center;
            align-items: center;
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
        .captcha-image {
            max-width: 100%;
            border-radius: 5px;
            margin: 15px 0;
        }
        input {
            padding: 12px;
            width: 85%;
            border-radius: 5px;
            border: 1px solid #68536f;
            font-size: 18px;
            text-align: center;
        }
        button, .refresh {
            display: inline-block;
            background: #74547e;
            color: white;
            padding: 12px 24px;
            border: none;
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
        <p>Enter the eight characters shown in the image
        to complete the security check.</p>

        {% if error %}
            <p class="error">{{ error }}</p>
        {% endif %}

        <img class="captcha-image"
             src="{{ url_for('captcha_image') }}"
             alt="Distorted CAPTCHA characters">

        <form method="POST" autocomplete="off">
            <input type="text"
                   name="answer"
                   maxlength="8"
                   placeholder="Enter characters"
                   required
                   autofocus>
            <button type="submit">Continue</button>
        </form>

        <a class="refresh" href="{{ url_for('refresh_captcha') }}">
            ↻ New Image
        </a>
    </div>
</body>
</html>
"""

SUCCESS_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Check Complete</title>
    <style>
        body {
            background: #101016;
            color: #dfbde3;
            font-family: Georgia, serif;
            text-align: center;
            padding: 15vh 20px;
        }
    </style>
</head>
<body>
    <h1>Security Check Complete</h1>
    <p>You have successfully solved the CAPTCHA.</p>
    <p>Discord role verification is not connected yet.</p>
</body>
</html>
"""


def generate_captcha():
    alphabet = string.ascii_uppercase + string.digits
    answer = "".join(
        secrets.choice(alphabet)
        for _ in range(CAPTCHA_LENGTH)
    )

    session["captcha_answer"] = answer
    session["captcha_created"] = time.time()
    session["captcha_attempts"] = 0
    session["captcha_passed"] = False


@app.get("/")
def home():
    if "captcha_answer" not in session:
        generate_captcha()

    return render_template_string(PAGE, error=None)


@app.get("/captcha.png")
def captcha_image():
    answer = session.get("captcha_answer")

    if not answer:
        generate_captcha()
        answer = session["captcha_answer"]

    image = ImageCaptcha(width=350, height=110)
    data = image.generate(answer)

    return Response(
        data.getvalue(),
        mimetype="image/png",
        headers={"Cache-Control": "no-store"},
    )


@app.get("/refresh")
def refresh_captcha():
    generate_captcha()
    return redirect(url_for("home"))


@app.post("/")
def verify():
    answer = session.get("captcha_answer")
    created = session.get("captcha_created", 0)
    attempts = session.get("captcha_attempts", 0)

    if not answer or time.time() - created > CAPTCHA_LIFETIME:
        generate_captcha()
        return render_template_string(
            PAGE,
            error="The CAPTCHA expired. Please try the new image.",
        ), 400

    if attempts >= MAX_ATTEMPTS:
        generate_captcha()
        return render_template_string(
            PAGE,
            error="Too many attempts. A new CAPTCHA has been generated.",
        ), 429

    session["captcha_attempts"] = attempts + 1
    submitted = request.form.get("answer", "").strip().upper()

    if not secrets.compare_digest(submitted, answer):
        return render_template_string(
            PAGE,
            error="Incorrect characters. Please try again.",
        ), 403

    session.pop("captcha_answer", None)
    session.pop("captcha_created", None)
    session.pop("captcha_attempts", None)
    session["captcha_passed"] = True

    return SUCCESS_PAGE


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
    )
