from __future__ import annotations

import xml.etree.cElementTree as et
from types import TracebackType
from typing import IO, Any, Dict, Iterator, List, Optional, Type, Union

import httpx
from pydantic import BaseModel

from . import _utils as utils
from .config import S3NS


class UploadPart(BaseModel, frozen=True):
    etag: str
    part_number: int


class MultipartUploadComplete(BaseModel, frozen=True):
    etag: str
    key: str
    bucket: str
    location: str


class MultipartUpload:
    key: str
    upload_id: str
    session: httpx.Client

    def __init__(self, key: str, *, session: httpx.Client) -> None:
        self.session = session
        self.key = key
        self.upload_id = ""

    def __enter__(self) -> MultipartUpload:
        self.begin()
        return self

    def __exit__(self, exc_type: Type[BaseException], exc_val: BaseException, exc_tb: TracebackType) -> None:
        if exc_type is None:
            self.complete()
        else:
            self.abort()

    def begin(self) -> None:
        req = self.session.build_request("POST", self.key, params={"uploads": None})
        response = self.session.send(req)
        utils.check_s3_response(response)

        root = et.fromstring(response.read())
        response.raise_for_status()
        self.upload_id = root.findtext("s3:UploadId", default="", namespaces=S3NS)

    def upload_part(
        self, part_num: int, file: Union[bytes, IO[Any], Iterator[bytes]], length: Optional[int] = None,
    ) -> UploadPart:
        headers: Dict[str, str] = {}
        if length is not None:
            headers["Content-Length"] = str(length)

        params = {"partNumber": part_num, "uploadId": self.upload_id}
        response = self.session.request("PUT", self.key, content=file, params=params, headers=headers)
        utils.check_s3_response(response)
        return UploadPart(etag=response.headers["ETag"], part_number=part_num)

    def complete(self, parts: Optional[List[UploadPart]] = None) -> MultipartUploadComplete:
        parts = sorted(parts or [x for x in self.iter_parts()], key=lambda x: x.part_number)

        data = "<CompleteMultipartUpload>"
        for part in parts:
            data += "<Part>"
            data += f"<PartNumber>{part.part_number}</PartNumber>"
            data += f"<ETag>{part.etag}</ETag>"
            data += "</Part>"
        data += "</CompleteMultipartUpload>"

        params = {"uploadId": self.upload_id}
        req = self.session.build_request("POST", self.key, params=params, content=data)
        response = self.session.send(req)
        utils.check_s3_response(response)

        root = et.fromstring(response.text)

        location = root.findtext("s3:Location", "", S3NS)
        bucket = root.findtext("s3:Bucket", "", S3NS)
        key = root.findtext("s3:Key", "", S3NS)
        e_tag = root.findtext("s3:ETag", "", S3NS)
        return MultipartUploadComplete(etag=e_tag, key=key, bucket=bucket, location=location)

    def abort(self) -> None:
        params = {"uploadId": self.upload_id}
        response = self.session.request("DELETE", self.key, params=params)
        utils.check_s3_response(response)

    def iter_parts(self, encoding: Optional[str] = None, max_parts: Optional[int] = None) -> Iterator[UploadPart]:
        more = True
        params = utils.filter_values({"uploadId": self.upload_id, "encoding-type": encoding, "max-parts": max_parts,})

        while more:
            req = self.session.build_request("GET", self.key, params=params)
            response = self.session.send(req)
            utils.check_s3_response(response)
            root = et.fromstring(response.text)

            more = root.findtext("s3:IsTruncated", "false", S3NS) == "true"
            if next_token := root.findtext("s3:NextPartNumberMarker", None, S3NS):
                params["part-number-marker"] = next_token

            for tag in root.findall("s3:Part", S3NS):
                args: Dict[str, Any] = dict(
                    etag=tag.findtext("s3:ETag", "", S3NS), part_number=tag.findtext("s3:PartNumber", 0, S3NS),
                )
                yield UploadPart(**args)
