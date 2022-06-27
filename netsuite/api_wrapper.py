import logging
import os
import requests
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import ClassVar, Union
from urllib.parse import quote_plus

import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key


@dataclass
class NetSuiteAuth:
    """Wraps all the bits needed for NetSuite authentication

    Request for auth token requires:
    - grant_type
    - client_assertion_type
    - client_assertion (generated from contents here; is the JWT bearer token with all the bits)

    Generating client_assertion requires:
    - header comprised of:
        - `kid` (cert_id)
        - `typ` (always "JWT")
        - `alg` ("RS256" with given cert gen, could change)
    - payload comprised of:
        - `iss` (client_id for integration)
        - `scope`
        - `aud` (account id???)
        - `exp` (cert expiration epoch seconds)
        - `iat` (cert issued epoch seconds)

    Authenticated request requires:
    - oauth_token
    
    """
    company_id: str
    certificate_id: str
    certificate_path: str
    key_path: str
    consumer_key: str
    consumer_secret: str
    key_password: Union[str, None] = None
    auth_scope: str = "restlets,rest_webservices,suite_analytics"
    access_token_expiration_minutes: int = 30

    # Constants used in constructing authorization requests
    GRANT_TYPE: ClassVar[str] = "client_credentials"
    CLIENT_ASSERTION_TYPE: ClassVar[str] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    # Constants used in constructing URLs for requests based on company_id
    HOST_URL_TEMPLATE = "https://{company_id}.suitetalk.api.netsuite.com"
    TOKEN_REQUEST_URL_TEMPLATE = "https://{company_id}.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token"

    def __post_init__(self):
        """After initialization of dataclass, sets JWT"""
        self.jwt = self._get_token_request_jwt()
        self.token_request_url = self.TOKEN_REQUEST_URL_TEMPLATE.format(company_id=self.company_id)
        self.host_url = self.HOST_URL_TEMPLATE.format(company_id=self.company_id)

    def _get_token_request_jwt(self) -> str:
        """Uses metadata in NetSuiteAuth to compose request jwt"""
        with open(self.key_path, "rb") as key_file:
            loaded_pkey = load_pem_private_key(key_file.read(), password=self.key_password)

        jwt_header = {
            "typ": "JWT",
            "alg": "RS256",
            "kid": self.certificate_id,
        }

        now_dt = datetime.utcnow()

        jwt_payload = {
            "iss": self.consumer_secret,
            "scope": self.auth_scope,
            "aud": self.company_id,
            "iat": int(now_dt.timestamp()),
            "exp": int((now_dt + timedelta(
                minutes=self.access_token_expiration_minutes
            )).timestamp())
        }

        encoded_jwt = jwt.encode(
            payload=jwt_payload,
            key=loaded_pkey,
            algorithm="RS256",
            headers=jwt_header
        )
        return encoded_jwt


class NetSuite:
    """Wrapper for Oracle NetSuite API

    Designed to utilize the Oauth2 Client-Credentials route for authorization at the moment.
    """
    def __init__(
        self,
        auth: NetSuiteAuth = None,
        logger: logging.Logger = None
    ):
        self._resolve_auth(auth)
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)

        self.access_token = None
        self.access_token_expires_at = datetime.utcnow()

    def _resolve_auth(self, injected_auth: NetSuiteAuth):
        """Given potentially injected authentication, resolve creds with os.environ if otherwise necessary

        """
        if injected_auth is not None:
            self.auth = injected_auth
        else:
            try:
                self.auth = NetSuiteAuth(
                    company_id=os.environ["NETSUITE_CID"],
                    certificate_id=os.environ["NETSUITE_CERTIFICATE_ID"],
                    certificate_path=os.environ["NETSUITE_CERTIFICATE_PATH"],
                    key_path=os.environ["NETSUITE_PRIVATE_KEY_PATH"],
                    consumer_key=os.environ["NETSUITE_CONSUMER_KEY"],
                    consumer_secret=os.environ["NETSUITE_CONSUMER_SECRET"],
                )
            except KeyError as ke:
                raise ValueError(
                    f"Could not resolve NetSuite credential from environment variable: {ke}\n"
                    "Please inject authentication via NetSuiteAuth class if not initializing with environment"
                )
    
    def _ensure_access_token_fresh(self):
        """If no access token or expired access token, retrieves a fresh one from the API with auth
        
        TODO: If there is a plan to add in thread safety via a lock on access key,
              there will need to be ensured timeouts on network requests
        """
        current_dt = datetime.utcnow()

        if self.access_token is None or current_dt >= self.access_token_expires_at:
            token_request_payload = (
                f"grant_type={quote_plus(self.auth.GRANT_TYPE)}"
                f"&client_assertion_type={quote_plus(self.auth.CLIENT_ASSERTION_TYPE)}"
                f"&client_assertion={self.auth.jwt}"
            )

            token_response = requests.post(
                self.auth.token_request_url,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                data=token_request_payload
            )
            token_response.raise_for_status()

    def get(
        self,
        url: str,
    ):
        """Make a GET request to the specified URL"""
        self._ensure_access_token_fresh()
        raise NotImplementedError("Haven't fleshed out GET yet!")
