class S3Exception(Exception):
    """Base class for S3 exceptions"""


class S3HTTPError(S3Exception):
    """Base class for S3 HTTP errors"""


class S3Error(S3Exception):
    def __init__(self, message: str, *, code: str = "", request_id: str = "", host_id: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.request_id = request_id
        self.host_id = host_id

    def __repr__(self) -> str:
        return f"[{self.code}] {self.request_id} {self.host_id} - {self.args[0]}"
