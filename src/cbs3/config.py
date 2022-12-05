from typing import Optional

import httpx
from pydantic import BaseModel, validator

from .credentials import AwsAuth

S3NS = {"s3": "http://s3.amazonaws.com/doc/2006-03-01/"}
MIN_MULTIPART_SIZE = 5 * 1024 * 1024


class BaseConfig(BaseModel):
    timeout: Optional[int] = None
    region: Optional[str] = None
    access_key: Optional[str]
    secret_key: Optional[str]
    session_token: Optional[str]

    def get_auth(self, service: str) -> httpx.Auth:
        return AwsAuth(
            service=service,
            access_key=self.access_key,
            secret_key=self.secret_key,
            session_token=self.session_token,
            region=self.region,
        )


class BucketConfig(BaseConfig):
    name: str
    endpoint: str = "s3.amazonaws.com"
    tls: bool = True
    multipart_threshold: int = MIN_MULTIPART_SIZE
    max_concurrency: int = 10
    anonymous: bool = False

    @validator("multipart_threshold")
    def multipart_threshold_validate(cls, v: int) -> int:
        return max(v, MIN_MULTIPART_SIZE)

    def get_base_url(self) -> str:
        protocol = "https" if self.tls else "http"
        return f"{protocol}://{self.name}.{self.endpoint}"


class QueueConfig(BaseConfig):
    queue_url: str
    api_version: str = "2012-11-05"
    max_number_of_messages: Optional[int] = None
    visibility_timeout: Optional[int] = None
    wait_time_seconds: Optional[int] = None


def create_aws_endpoint(queue_name: str, account_id: int, region: str) -> str:
    return f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"
