from typing import Any, Optional

import httpx
from typing_extensions import Self


class BaseClient:
    def __init__(self, base_url: str, auth: Optional[httpx.Auth] = None, timeout: Optional[int] = None):
        self._base_url = base_url
        self._auth = auth
        self._timeout = timeout
        self._session = None

    @property
    def session(self) -> httpx.Client:
        if not self._session:
            self._session = httpx.Client(base_url=self._base_url, timeout=self._timeout, auth=self._auth)
        return self._session

    def __enter__(self) -> Self:
        self.session.__enter__()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.session.__exit__(*exc_info)
        self._session = None

    def close(self) -> None:
        if self._session:
            self._session.close()
            self._session = None
