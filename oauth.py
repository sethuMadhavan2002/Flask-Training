from flask import Flask, redirect, url_for, session, request
from flask_oauthlib.client import OAuth
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

oauth = OAuth(app)

google = oauth.remote_app(
    "google",
    consumer_key="109284660773-fr4nu613834ustednninm3oipck23a9s.apps.googleusercontent.com",
    consumer_secret="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",
    request_token_params={
        "scope": "email",
    },
    base_url="https://www.googleapis.com/oauth2/v1/",
    request_token_url=None,
    access_token_method="POST",
    access_token_url="https://accounts.google.com/o/oauth2/token",
    authorize_url="https://accounts.google.com/o/oauth2/auth",
)


@app.route("/")
def index():
    if "google_token" in session:
        user = google.get("userinfo")
        return "Logged in as : " + user.data["email"]
    return "Not Logged in"


@app.route("/login")
def login():
    return google.authorize(callback=url_for("authorized", _external=True))


@app.route("/logout")
def logout():
    session.pop("google_token", None)
    return "Logged out"


@app.route("/login/authorized")
def authorized():
    response = google.authorized_response()
    if response is None or response.get("access_token") is None:
        return f"Access denied : reason={request.args['error_reason']} error={request.args['error_description']}"
    session["google_token"] = (response["access_token"], "")
    user = google.get("userinfo")
    return "Logged in as : " + user.data["email"]


@google.tokengetter
def get_oauth_token():
    return session.get("google_token")


if __name__ == "__main__":
    app.run(debug=True)
