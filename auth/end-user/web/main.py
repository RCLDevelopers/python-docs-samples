# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""An example web application that obtains authorization and credentials from
an end user.

This sample is used on
https://developers.google.com/identity/protocols/OAuth2WebServer. Please
refer to that page for instructions on using this sample.

Notably, you'll need to obtain a OAuth2.0 client secrets file and set the
``GOOGLE_CLIENT_SECRETS`` environment variable to point to that file.
"""

import os
from typing import Tuple, Dict

import flask
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from flask import Flask, redirect, session, url_for, request

# Configuration
CLIENT_SECRETS_FILENAME = os.environ["GOOGLE_CLIENT_SECRETS"]
SCOPES = ["email", "profile"]
SECRET_KEY = "TODO: replace with a secret value"

app = Flask(__name__)
app.secret_key = SECRET_KEY


def get_oauth2_credentials() -> Dict[str, str]:
    """
    Retrieve the OAuth2 credentials from the session.

    Returns:
        A dictionary containing the OAuth2 credentials.
    """
    if "credentials" not in session:
        return {}
    return session["credentials"]


def save_oauth2_credentials(credentials: google.oauth2.credentials.Credentials) -> None:
    """
    Save the OAuth2 credentials to the session.

    Args:
        credentials: The OAuth2 credentials to be saved.
    """
    session["credentials"] = {
        "token": credentials.token,
        "refresh_token": credentials.refresh_token,
        "token_uri": credentials.token_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret,
        "scopes": credentials.scopes,
    }


def get_oauth2_flow() -> google_auth_oauthlib.flow.Flow:
    """
    Create an OAuth2 flow instance.

    Returns:
        An OAuth2 flow instance.
    """
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILENAME, scopes=SCOPES
    )
    flow.redirect_uri = url_for("oauth2callback", _external=True)
    return flow


@app.route("/")
def index():
    """
    Retrieve the user's basic information from the Google OAuth2.0 API.
    """
    credentials = google.oauth2.credentials.Credentials(**get_oauth2_credentials())
    client = googleapiclient.discovery.build("oauth2", "v2", credentials=credentials)
    response = client.userinfo().v2().me().get().execute()
    return str(response)


@app.route("/authorize")
def authorize():
    """
    Start the OAuth2 authorization flow.
    """
    flow = get_oauth2_flow()
    authorization_url, state = flow.authorization_url(
        access_type="offline", include_granted_scopes="true"
    )
    session["state"] = state
    return redirect(authorization_url)


@app.route("/oauth2callback")
def oauth2callback():
    """
    Handle the OAuth2 callback after the authorization flow.
    """
    state = session["state"]
    flow = get_oauth2_flow()
    flow.state = state
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    save_oauth2_credentials(credentials)
    return redirect(url_for("index"))


if __name__ == "__main__":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    app.run("localhost", 8080, debug=True)
