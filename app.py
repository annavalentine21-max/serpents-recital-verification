import os

import requests
from flask import Flask, render_template_string, request

app = Flask(__name__)

SITE_KEY = os.environ["TURNSTILE_SITE_KEY"]
SECRET_KEY = os.environ["TURNSTILE_SECRET_KEY"]

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Serpent's Recital | Verification</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js"
            async defer></script>
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
            padding: 40px;
            max-width: 420px;
            width: 85%;
            text-align: center;
        }
        h1 { color: #dfbde3; }
        p { line-height: 1.6; }
        button {
            background: #74547e;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            margin-top: 20px;
        }
        .cf-turnstile {
            display: flex;
            justify-content: center;
            margin-top: 24px;
        }
    </style>
</head>
<body>
    <div class="panel">
        <h1>Serpent's Recital</h1>
        <p>Complete the security check below to continue
        your Discord server verification.</p>

        <form method="POST">
            <div class="cf-turnstile"
                 data-sitekey="{{ site_key }}"></div>
            <button type="submit">Continue</button>
        </form>
    </div>
</body>
</html>
"""


@app.get("/")
def home():
    return render_template_string(PAGE, site_key=SITE_KEY)


@app.post("/")
def verify():
    captcha_token = request.form.get("cf-turnstile-response", "")

    if not captcha_token:
        return "Please complete the security check.", 400

    try:
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={
                "secret": SECRET_KEY,
                "response": captcha_token,
            },
            timeout=10,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError):
        return "Verification service unavailable. Contact staff.", 503

    if not result.get("success"):
        return "Security check failed. Please try again.", 403

    return (
        "Security check passed! Discord role verification "
        "is not connected yet. Please contact staff."
    )


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "8080")),
    )
