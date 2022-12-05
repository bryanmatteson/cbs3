import hmac
import logging
import os
from datetime import datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Generator, Optional, Tuple, cast
from urllib.parse import parse_qsl, urlencode

import cbasyncio
import httpx

MANDATORY_REFRESH_TIMEOUT = 10 * 60  # 10 min
ADVISORY_REFRESH_TIMEOUT = 15 * 60  # 15 min

METADATA_BASE_URL = "http://169.254.169.254"
METADATA_BASE_URL_IPv6 = "http://[fd00:ec2::254]"

logger = logging.getLogger("cbs3")


class AwsAuth(httpx.Auth):
    access_key: Optional[str]
    secret_key: Optional[str]
    session_token: Optional[str]
    expires: Optional[datetime]
    region: str
    service: str

    def __init__(
        self,
        service: str,
        *,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        self.service = service
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token or os.getenv("AWS_SESSION_TOKEN", None)
        self.expires = None
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    async def async_auth_flow(self, request: httpx.Request) -> AsyncGenerator[httpx.Request, httpx.Response]:
        if not self.access_key or not self.secret_key:
            self.access_key, self.secret_key = get_aws_credentials_from_env()
            if not self.access_key or not self.secret_key:
                self.access_key, self.secret_key = await cbasyncio.to_thread.run_sync(get_aws_credentials_from_file)

        flow = self.auth_flow(request)
        request = next(flow)

        while True:
            response = yield request
            try:
                await response.aread()
                request = flow.send(response)
            except StopIteration:
                break

    def sync_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if not self.access_key or not self.secret_key:
            self.access_key, self.secret_key = get_aws_credentials_from_env()
            if not self.access_key or not self.secret_key:
                self.access_key, self.secret_key = get_aws_credentials_from_file()

        flow = self.auth_flow(request)
        request = next(flow)

        while True:
            response = yield request
            try:
                response.read()
                request = flow.send(response)
            except StopIteration:
                break

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if self.needs_imds_refresh():
            logger.info("Fetching AWS credentials from IMDS")

            flow = self.imds_flow()
            req = next(flow)

            while True:
                response = yield req
                try:
                    req = flow.send(response)
                except StopIteration:
                    break

        if self.access_key and self.secret_key:
            auth = SigV4Auth(
                self.service,
                access_key=self.access_key,
                secret_key=self.secret_key,
                session_token=self.session_token,
                region=self.region,
            )
            request = auth.add_auth(request)

        yield request

    def imds_flow(self) -> Generator[httpx.Request, httpx.Response, None]:
        response = yield (req := self.fetch_metadata_token_request())

        token: Optional[str] = None
        if response.status_code == 200:
            token = response.text
        elif response.status_code == 400:
            raise httpx.HTTPStatusError("bad idms request", request=req, response=response)
        elif response.status_code in (404, 403, 405):
            logger.info("Got %d from IMDS, assuming no token", response.status_code)
        elif response.status_code != 200:
            raise httpx.HTTPStatusError("unknown idms error", request=req, response=response)

        response = yield (req := self.get_iam_role_request(token))
        if not response.is_success:
            raise httpx.HTTPStatusError("error getting iam role", request=req, response=response)

        role_name = response.text
        response = yield self.get_iam_creds_request(role_name, token)
        if not response.is_success:
            raise httpx.HTTPStatusError("error getting iam creds", request=req, response=response)

        data: Dict[str, Any] = response.json()
        self.access_key = data["AccessKeyId"]
        self.secret_key = data["SecretAccessKey"]
        self.session_token = data.get("Token")
        if expiration := data.get("Expiration"):
            self.expires = datetime.strptime(expiration, "%Y-%m-%dT%H:%M:%SZ")

    def needs_imds_refresh(self) -> bool:
        if not self.access_key or not self.secret_key:
            return True
        return self.expires is not None and self.expires < datetime.utcnow()

    def update_tokens(self, response: httpx.Response) -> None:
        record = response.json()

        if "auth" not in record:
            raise ValueError("No auth data in response")

        auth = record["auth"]
        if not isinstance(auth, dict):
            raise ValueError(f"Invalid auth data in response: {auth!r}")

        auth = cast(Dict[str, Any], auth)

        self.token = auth["client_token"]
        if lease_duration := auth["lease_duration"]:
            self.expires = datetime.now() + timedelta(seconds=lease_duration)
        else:
            self.expires = None

    def fetch_metadata_token_request(self) -> httpx.Request:
        headers = {"x-aws-ec2-metadata-token-ttl-seconds": "21600"}
        return httpx.Request("PUT", f"{METADATA_BASE_URL}/latest/api/token", headers=headers)

    def get_iam_role_request(self, token: Optional[str] = None) -> httpx.Request:
        headers = {}
        if token is not None:
            headers["x-aws-ec2-metadata-token"] = token

        return httpx.Request("GET", f"{METADATA_BASE_URL}/latest/meta-data/iam/security-credentials/", headers=headers)

    def get_iam_creds_request(self, role_name: str, token: Optional[str]) -> httpx.Request:
        headers = {}
        if token is not None:
            headers["x-aws-ec2-metadata-token"] = token

        url = f"{METADATA_BASE_URL}/latest/meta-data/iam/security-credentials/{role_name}"
        return httpx.Request("GET", url, headers=headers)


class SigV4Auth(object):
    region: str
    session_token: Optional[str]
    secret_key: str
    access_key: str
    service: str

    def __init__(
        self,
        service: str,
        *,
        access_key: str,
        secret_key: str,
        session_token: Optional[str] = None,
        region: Optional[str] = None,
    ) -> None:
        self.service = service
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token or os.getenv("AWS_SESSION_TOKEN", None)
        self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")

    def add_auth(self, req: httpx.Request) -> httpx.Request:
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        req.headers["X-Amz-Date"] = timestamp

        if self.session_token:
            req.headers["X-Amz-Security-Token"] = self.session_token

        params: Dict[str, Any] = dict(parse_qsl(req.url.query.decode("utf-8"), keep_blank_values=True))
        query = urlencode(sorted(params.items()))

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
        canonical_headers = "".join("{0}:{1}\n".format(k.lower(), req.headers[k]) for k in sorted(req.headers))
        signed_headers = ";".join(k.lower() for k in sorted(req.headers))
        payload_hash = sha256(req.content).hexdigest()
        canonical_request = "\n".join(
            [req.method, req.url.path or "/", query, canonical_headers, signed_headers, payload_hash]
        )

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = "/".join([timestamp[0:8], self.region, self.service, "aws4_request"])
        canonical_request_hash = sha256(canonical_request.encode("utf-8")).hexdigest()
        string_to_sign = "\n".join([algorithm, timestamp, credential_scope, canonical_request_hash])

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
        key = "AWS4{0}".format(self.secret_key).encode("utf-8")
        key = hmac.new(key, timestamp[0:8].encode("utf-8"), sha256).digest()
        key = hmac.new(key, self.region.encode("utf-8"), sha256).digest()
        key = hmac.new(key, self.service.encode("utf-8"), sha256).digest()
        key = hmac.new(key, "aws4_request".encode("utf-8"), sha256).digest()
        signature = hmac.new(key, string_to_sign.encode("utf-8"), sha256).hexdigest()

        # https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
        authorization = "{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}".format(
            algorithm,
            self.access_key,
            credential_scope,
            signed_headers,
            signature,
        )

        req.headers["X-Amz-Content-Sha256"] = payload_hash
        req.headers["Authorization"] = authorization
        return req


def get_aws_credentials_from_env() -> Tuple[Optional[str], Optional[str]]:
    access_key = os.getenv("AWS_ACCESS_KEY_ID", None)
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", None)
    return (access_key, secret_key)


def get_aws_credentials_from_file() -> Tuple[Optional[str], Optional[str]]:
    credentials_path = Path(os.getenv("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")).expanduser()
    if not credentials_path.exists() or not credentials_path.is_file():
        return (None, None)

    import configparser

    with credentials_path.open() as f_in:
        config = configparser.ConfigParser()
        config.read_file(f_in, source=credentials_path.as_posix())
        return (
            config.get("default", "aws_access_key_id", fallback=None),
            config.get("default", "aws_secret_access_key", fallback=None),
        )


# class CredentialDict(TypedDict):
#     access_key_id: str
#     secret_access_key: str
#     session_token: str
#     expiration: str


# class Credentials:
#     def __init__(self, access_key: str, secret_key: str, token: Optional[str] = None):
#         self._access_key = access_key
#         self._secret_key = secret_key
#         self._token = token

#     @property
#     def access_key(self) -> str:
#         return self._access_key

#     @property
#     def secret_key(self) -> str:
#         return self._secret_key

#     @property
#     def token(self) -> Optional[str]:
#         return self._token

#     def snapshot(self) -> "Credentials":
#         return self


# class RefreshableCredentials(Credentials):
#     def __init__(
#         self,
#         access_key: Optional[str] = None,
#         secret_key: Optional[str] = None,
#         token: Optional[str] = None,
#         expiry_time: Optional[datetime] = None,
#         refresh_using: Optional[Callable[[], CredentialDict]] = None,
#     ) -> None:
#         super().__init__(access_key or "", secret_key or "", token)
#         self._refresh_using = refresh_using
#         self._expiry_time = expiry_time
#         self._refresh_lock = threading.Lock()

#     @property
#     def access_key(self) -> str:
#         self._refresh()
#         return self._access_key

#     @property
#     def secret_key(self) -> str:
#         self._refresh()
#         return self._secret_key

#     @property
#     def token(self) -> Optional[str]:
#         self._refresh()
#         return self._token

#     def _seconds_remaining(self) -> float:
#         if self._expiry_time is None:
#             return math.inf
#         delta = self._expiry_time - datetime.now(timezone.utc)
#         return delta.total_seconds()

#     def refresh_needed(self, refresh_in: Optional[int] = None) -> bool:
#         if self._expiry_time is None or self._refresh_using is None:
#             return False

#         if refresh_in is None:
#             refresh_in = ADVISORY_REFRESH_TIMEOUT

#         if self._seconds_remaining() >= refresh_in:
#             return False

#         return True

#     def _is_expired(self) -> bool:
#         return self.refresh_needed(refresh_in=0)

#     def _refresh(self) -> None:
#         if not self.refresh_needed(ADVISORY_REFRESH_TIMEOUT):
#             return

#         if self._refresh_lock.acquire(False):
#             try:
#                 if not self.refresh_needed(ADVISORY_REFRESH_TIMEOUT):
#                     return
#                 is_mandatory_refresh = self.refresh_needed(MANDATORY_REFRESH_TIMEOUT)
#                 self._protected_refresh(is_mandatory=is_mandatory_refresh)
#                 return
#             finally:
#                 self._refresh_lock.release()
#         elif self.refresh_needed(MANDATORY_REFRESH_TIMEOUT):
#             with self._refresh_lock:
#                 if not self.refresh_needed(MANDATORY_REFRESH_TIMEOUT):
#                     return
#                 self._protected_refresh(is_mandatory=True)

#     def _protected_refresh(self, is_mandatory: bool) -> None:
#         assert self._refresh_using is not None

#         try:
#             metadata = self._refresh_using()
#         except Exception:
#             if is_mandatory:
#                 raise
#             return

#         self._access_key = metadata["access_key_id"]
#         self._secret_key = metadata["secret_access_key"]
#         self._token = metadata["session_token"]
#         self._expiry_time = parse(metadata["expiration"])

#         if self._is_expired():
#             raise RuntimeError("refreshed credentials are still expired")

#     def snapshot(self) -> Credentials:
#         self._refresh()
#         return Credentials(self._access_key, self._secret_key, self._token)


# class AwsSigV4Auth(httpx.Auth):
#     region: str
#     creds: Optional[Credentials]
#     service: str

#     def __init__(
#         self,
#         service: str,
#         *,
#         access_key: Optional[str] = None,
#         secret_key: Optional[str] = None,
#         session_token: Optional[str] = None,
#         region: Optional[str] = None,
#     ) -> None:
#         self.service = service

#         if access_key is not None and secret_key is not None:
#             self.creds = Credentials(access_key, secret_key, session_token or os.getenv("AWS_SESSION_TOKEN", None))
#         else:
#             self.creds = (
#                 get_aws_credentials_from_env() or
#                   get_aws_credentials_from_file() or
#                   get_aws_credentials_from_metadata()
#             )
#         self.region = region or os.getenv("AWS_DEFAULT_REGION", "us-east-1")

#     def auth_flow(self, req: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
#         if not self.creds:
#             yield req
#             return

#         timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
#         req.headers["X-Amz-Date"] = timestamp

#         creds = self.creds.snapshot()

#         if creds.token:
#             req.headers["X-Amz-Security-Token"] = creds.token

#         params: Dict[str, Any] = dict(parse_qsl(req.url.query.decode("utf-8"), keep_blank_values=True))
#         query = urlencode(sorted(params.items()))

#         # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
#         canonical_headers = "".join("{0}:{1}\n".format(k.lower(), req.headers[k]) for k in sorted(req.headers))
#         signed_headers = ";".join(k.lower() for k in sorted(req.headers))
#         payload_hash = sha256(req.content).hexdigest()
#         canonical_request = "\n".join(
#             [req.method, req.url.path or "/", query, canonical_headers, signed_headers, payload_hash]
#         )

#         # https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
#         algorithm = "AWS4-HMAC-SHA256"
#         credential_scope = "/".join([timestamp[0:8], self.region, self.service, "aws4_request"])
#         canonical_request_hash = sha256(canonical_request.encode("utf-8")).hexdigest()
#         string_to_sign = "\n".join([algorithm, timestamp, credential_scope, canonical_request_hash])

#         # https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
#         key = "AWS4{0}".format(creds.secret_key).encode("utf-8")
#         key = hmac.new(key, timestamp[0:8].encode("utf-8"), sha256).digest()
#         key = hmac.new(key, self.region.encode("utf-8"), sha256).digest()
#         key = hmac.new(key, self.service.encode("utf-8"), sha256).digest()
#         key = hmac.new(key, "aws4_request".encode("utf-8"), sha256).digest()
#         signature = hmac.new(key, string_to_sign.encode("utf-8"), sha256).hexdigest()

#         # https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
#         authorization = "{0} Credential={1}/{2}, SignedHeaders={3}, Signature={4}".format(
#             algorithm,
#             creds.access_key,
#             credential_scope,
#             signed_headers,
#             signature,
#         )

#         req.headers["X-Amz-Content-Sha256"] = payload_hash
#         req.headers["Authorization"] = authorization
#         yield req


# class InstanceMetadataService:
#     _session: Optional[httpx.Client]

#     def __init__(self, *, base_url: str = METADATA_BASE_URL, timeout: int = 1) -> None:
#         self._timeout = timeout
#         self._base_url = base_url
#         self._session = None
#         self._logger = logging.getLogger("imds")

#     @property
#     def session(self) -> httpx.Client:
#         if not self._session:
#             self._session = httpx.Client(base_url=self._base_url, timeout=self._timeout)
#         return self._session

#     def get_credentials(self) -> CredentialDict:
#         token = self.fetch_metadata_token()
#         role_name = self.get_iam_role(token)
#         return self.fetch_credentials(role_name, token)

#     def fetch_credentials(self, role_name: str, token: Optional[str] = None) -> CredentialDict:
#         headers = {}
#         if token is not None:
#             headers["x-aws-ec2-metadata-token"] = token

#         url = f"latest/meta-data/iam/security-credentials/{role_name}"
#         request = self.session.build_request("GET", url, headers=headers)
#         response = self.session.send(request)
#         response.raise_for_status()

#         data: Dict[str, Any] = response.json()
#         return CredentialDict(
#             access_key_id=data["AccessKeyId"],
#             secret_access_key=data["SecretAccessKey"],
#             session_token=data["Token"],
#             expiration=data["Expiration"],
#         )

#     def fetch_metadata_token(self) -> Optional[str]:
#         headers = {"x-aws-ec2-metadata-token-ttl-seconds": "21600"}
#         request = self.session.build_request("PUT", "latest/api/token", headers=headers)
#         response = self.session.send(request)
#         if response.status_code == 200:
#             return response.text

#         if response.status_code in (404, 403, 405):
#             return None

#         response.raise_for_status()

#     def get_iam_role(self, token: Optional[str] = None) -> str:
#         headers = {}
#         if token is not None:
#             headers["x-aws-ec2-metadata-token"] = token

#         request = self.session.build_request("GET", "latest/meta-data/iam/security-credentials/", headers=headers)
#         response = self.session.send(request)
#         response.raise_for_status()
#         return response.text


# def get_aws_credentials_from_env() -> Optional[Credentials]:
#     access_key = os.getenv("AWS_ACCESS_KEY_ID", None)
#     secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", None)
#     if access_key and secret_key:
#         return Credentials(access_key, secret_key, os.getenv("AWS_SESSION_TOKEN", None))
#     return None


# def get_aws_credentials_from_file() -> Optional[Credentials]:
#     credentials_path = Path(os.getenv("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")).expanduser()
#     if not credentials_path.exists() or not credentials_path.is_file():
#         return None

#     import configparser

#     with credentials_path.open() as f_in:
#         config = configparser.ConfigParser()
#         config.read_file(f_in, source=credentials_path.as_posix())
#         if access_key := config.get("default", "aws_access_key_id", fallback=None):
#             if secret_key := config.get("default", "aws_secret_access_key", fallback=None):
#                 return Credentials(access_key, secret_key, config.get("default", "aws_session_token", fallback=None))
#     return None


# def get_aws_credentials_from_metadata() -> Optional[Credentials]:
#     imds = InstanceMetadataService()
#     try:
#         creds = imds.get_credentials()
#     except Exception as e:
#         logging.getLogger("imds").error("Failed to get credentials from metadata: %s", e)
#         return None

#     return RefreshableCredentials(
#         access_key=creds["access_key_id"],
#         secret_key=creds["secret_access_key"],
#         token=creds["session_token"],
#         expiry_time=parse(creds["expiration"]),
#         refresh_using=imds.get_credentials,
#     )
