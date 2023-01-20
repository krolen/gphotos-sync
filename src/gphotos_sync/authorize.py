import logging
from json import JSONDecodeError, dump, load
from pathlib import Path
from typing import List, Optional

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

from requests.adapters import HTTPAdapter
from requests_oauthlib import OAuth2Session
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)

class Authorize:
    def __init__(
            self,
            scope: List[str],
            token_file: Path,
            max_retries: int = 5
    ):
        """A very simple class to handle Google API authorization flow
        for the requests library. Includes saving the token and automatic
        token refresh.

        Args:
            scope: list of the scopes for which permission will be granted
            token_file: full path of a file in which the user token will be
            placed. After first use the previous token will also be read in from
            this file
        """
        self.max_retries = max_retries
        self.scope: List[str] = scope
        self.token_file: Path = token_file
        self.session = None
        self.creds: Credentials = None

        try:
            self.reload_creds()

        except (Exception):
            print("missing or bad token file: {}".format(token_file))
            exit(1)

    def _save_creds(self, creds: Credentials):
        with self.token_file.open("w") as stream:
            stream.write(creds.to_json())
        self.token_file.chmod(0o600)

    def reload_creds(self):
        creds = Credentials.from_authorized_user_file(self.token_file, self.scope)
        if creds.expired and creds.refresh_token:
            creds.refresh(Request())
            self._save_creds(creds)
        self.load_creds()

    def load_creds(self):
        with self.token_file.open("r") as stream:
            self.creds = Credentials.from_authorized_user_file(self.token_file, self.scope)

    def authorize(self):
        """Initiates OAuth2 authentication and authorization flow"""
        self.reload_creds()

        oauth2_token = {
            "access_token": self.creds.token,
            "refresh_token": self.creds.refresh_token,
            "token_type": "Bearer",
            "scope": self.scope,
            "expires_at": self.creds.expiry.timestamp(),
        }

        self.session = OAuth2Session(
            self.creds.client_id,
            token=oauth2_token,
            auto_refresh_url=self.creds.token_uri,
            auto_refresh_kwargs= {
                "client_id": self.creds.client_id,
                "client_secret": self.creds.client_secret,
            },
            # token_updater=self.save_token,
        )

        # set up the retry behaviour for the authorized session
        retries = Retry(
            total=self.max_retries,
            backoff_factor=5,
            status_forcelist=[500, 502, 503, 504, 429],
            allowed_methods=frozenset(["GET", "POST"]),
            raise_on_status=False,
            respect_retry_after_header=True,
        )
        # apply the retry behaviour to our session by replacing the default HTTPAdapter
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
