from __future__ import annotations

import asyncio
import io
import itertools
import mimetypes
import xml.etree.ElementTree as et
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import (
    IO,
    Any,
    AsyncIterable,
    AsyncIterator,
    Dict,
    Iterable,
    Iterator,
    List,
    Literal,
    Mapping,
    Optional,
    Union,
    overload,
)

import httpx
from cbasyncio import Asyncer, AsyncerContextManager, AsyncFile, Stream, aiter, anext, to_thread
from cbasyncio.utils import StreamIterable
from pydantic import BaseModel, validator

from ._utils import calc_cache_control, check_s3_response, decode_datetime, filter_values
from .client import BaseClient
from .config import MIN_MULTIPART_SIZE, S3NS, BucketConfig
from .multipart import MultipartUpload, UploadPart


class ObjectMetadata(BaseModel, frozen=True, arbitrary_types_allowed=True):
    etag: str
    name: str
    size: int
    last_modified: Optional[datetime]
    storage_class: str = ""
    content_type: str = "application/octet-stream"

    @validator("last_modified", pre=True)
    def time_validate(cls, v: Optional[str]) -> Optional[datetime]:
        return decode_datetime(v) if v else None


ObjectMetadata.update_forward_refs()


class Object:
    _bucket: Bucket
    _name: str
    _metadata: Optional[ObjectMetadata]

    def __init__(self, bucket: Bucket, name: str, *, metadata: Optional[ObjectMetadata] = None) -> None:
        self._bucket = bucket
        self._name = name
        self._metadata = metadata
        self._loaded = False

    def load(self) -> Object:
        self._metadata = self._bucket.metadata(self._name)
        return self

    @property
    def metadata(self) -> ObjectMetadata:
        if not self._metadata:
            self._metadata = self._bucket.metadata(self._name)
        return self._metadata

    @property
    def name(self) -> str:
        return self._name


class Bucket(BaseClient):
    _name: str
    _config: BucketConfig

    @property
    def name(self) -> str:
        return self._name

    @overload
    def __init__(self, config: BucketConfig, /) -> None:
        ...

    @overload
    def __init__(
        self,
        bucket: str,
        /,
        *,
        endpoint: str = "s3.amazonaws.com",
        tls: bool = True,
        timeout: Optional[int] = ...,
        region: Optional[str] = ...,
        access_key: Optional[str] = ...,
        secret_key: Optional[str] = ...,
        session_token: Optional[str] = ...,
        multipart_threshold: int = ...,
        max_concurrency: int = ...,
        anonymous: bool = ...,
    ) -> None:
        ...

    def __init__(
        self,
        bucket: Union[BucketConfig, str],
        /,
        *,
        endpoint: str = "s3.amazonaws.com",
        tls: bool = True,
        timeout: Optional[int] = None,
        region: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        multipart_threshold: int = MIN_MULTIPART_SIZE,
        max_concurrency: int = 10,
        anonymous: bool = False,
    ) -> None:
        if isinstance(bucket, BucketConfig):
            self._config = bucket
            self._name = bucket.name
        else:
            self._config = BucketConfig(
                name=bucket,
                endpoint=endpoint,
                tls=tls,
                timeout=timeout,
                region=region,
                multipart_threshold=multipart_threshold,
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                max_concurrency=max_concurrency,
                anonymous=anonymous,
            )
            self._name = bucket
        auth = self._config.get_auth("s3") if not self._config.anonymous else None
        super().__init__(self._config.get_base_url(), auth, self._config.timeout)

    def object(self, key: str) -> Object:
        return Object(self, key)

    def metadata(self, key: str) -> ObjectMetadata:
        response = self.session.request("HEAD", key)
        check_s3_response(response)

        args: Dict[str, Any] = filter_values(
            dict(
                name=key,
                size=response.headers["Content-Length"],
                last_modified=response.headers["Last-Modified"],
                etag=response.headers["ETag"],
                storage_class=response.headers.get("x-amz-storage-class", ""),
                content_type=response.headers.get("Content-Type", "application/octet-stream"),
            )
        )
        return ObjectMetadata(**args)

    def download(self, key: str, target: io.RawIOBase, *, buffer_size: int = io.DEFAULT_BUFFER_SIZE) -> int:
        with self.session.stream("GET", key) as response:
            check_s3_response(response)
            return sum(target.write(chunk) or 0 for chunk in response.iter_bytes(chunk_size=buffer_size))
        return 0

    def get(self, key: str) -> bytes:
        response = self.session.request("GET", key)
        check_s3_response(response)
        return response.read()

    def stream(self, key: str, *, chunk_size: int = io.DEFAULT_BUFFER_SIZE) -> Iterator[bytes]:
        with self.session.stream("GET", key) as response:
            check_s3_response(response)
            for chunk in response.iter_bytes(chunk_size=chunk_size):
                yield chunk

    def put(
        self,
        key: str,
        data: Union[str, bytes, Iterator[bytes]],
        *,
        expires: Union[timedelta, int, Literal["max"], None] = None,
        content_type: Optional[str] = None,
        public: bool = False,
    ) -> None:
        headers = {}
        if expires is not None:
            headers["Cache-Control"] = calc_cache_control(expires, public)

        if content_type is not None:
            headers["Content-Type"] = content_type
        elif mime_type := mimetypes.guess_type(key)[0]:
            headers["Content-Type"] = mime_type
        else:
            headers["Content-Type"] = "application/octet-stream"

        if public:
            headers["X-Amz-Acl"] = "public-read"

        response = self.session.request("PUT", key, content=data, headers=headers)
        check_s3_response(response)

    def upload(
        self,
        key: str,
        data: Union[str, bytes, Iterable[bytes], io.RawIOBase],
        *,
        expires: Union[timedelta, int, Literal["max"], None] = None,
        content_type: Optional[str] = None,
        public: bool = False,
    ) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")

        if isinstance(data, bytes):
            data = (data[i : i + io.DEFAULT_BUFFER_SIZE] for i in range(0, len(data), io.DEFAULT_BUFFER_SIZE))

        stream = StreamIterable(data).iter_chunks(self._config.multipart_threshold)

        chunk = next(stream, b"")
        if len(chunk) < self._config.multipart_threshold:
            return self.put(key, chunk, expires=expires, content_type=content_type, public=public)

        stream = itertools.chain([chunk], stream)

        parts: List[UploadPart] = []
        uploader = MultipartUpload(key, session=self.session)
        uploader.begin()

        try:
            with ThreadPoolExecutor(max_workers=self._config.max_concurrency) as executor:
                futures_to_parts = {
                    executor.submit(uploader.upload_part, part_num, chunk, len(chunk)): part_num
                    for part_num, chunk in enumerate(stream, start=1)
                }
                for future in as_completed(futures_to_parts):
                    part_num = futures_to_parts[future]
                    try:
                        parts.append(future.result())
                    except Exception as exc:
                        print("error uploading part {}: {}".format(part_num, exc))

        except BaseException as e:
            uploader.abort()
            raise e
        else:
            uploader.complete(parts)

    def list(self, prefix: Optional[str] = None) -> Iterator[Object]:
        more = True
        params = filter_values({"prefix": prefix, "list-type": "2", "encoding-type": "url"})

        while more:
            response = self.session.request("GET", "", params=params)
            check_s3_response(response)
            root = et.fromstring(response.content)

            more = root.findtext("s3:IsTruncated", "false", S3NS) == "true"
            if next_token := root.findtext("s3:NextContinuationToken", None, S3NS):
                params["continuation-token"] = next_token

            for tag in root.findall("s3:Contents", S3NS):
                args: Dict[str, Any] = filter_values(
                    dict(
                        name=tag.findtext("s3:Key", None, S3NS),
                        size=tag.findtext("s3:Size", None, S3NS),
                        last_modified=tag.findtext("s3:LastModified", None, S3NS),
                        etag=tag.findtext("s3:ETag", None, S3NS),
                        storage_class=tag.findtext("s3:StorageClass", None, S3NS),
                    )
                )
                metadata = ObjectMetadata(**args)
                yield Object(self, metadata.name, metadata=metadata)

    def delete(self, key: str) -> None:
        response = self.session.request("DELETE", key)
        check_s3_response(response)

    def copy(
        self,
        key: str,
        *,
        to_key: str,
        to_bucket: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        public: bool = False,
    ) -> None:
        headers = {"x-amz-copy-source": f"{self.name}/{key}"}
        if not metadata:
            headers["x-amz-metadata-directive"] = "COPY"
        else:
            headers["x-amz-metadata-directive"] = "REPLACE"

        if public:
            headers["x-amz-acl"] = "public-read"

        if metadata:
            headers.update(metadata)

        req = self.session.build_request("PUT", to_key, headers=headers)
        if to_bucket:
            protocol = "https" if self._config.tls else "http"
            req.url = httpx.URL(f"{protocol}://{to_bucket}.{self._config.endpoint}/{to_key}")

        response = self.session.send(req)
        check_s3_response(response)

    def __repr__(self) -> str:
        return f'Bucket(name="{self._name}")'


class AsyncBucket(AsyncerContextManager[Bucket]):
    @overload
    def __init__(self, config: BucketConfig, /) -> None:
        ...

    @overload
    def __init__(self, bucket: Bucket, /) -> None:
        ...

    @overload
    def __init__(
        self,
        bucket: str,
        /,
        *,
        endpoint: str = ...,
        tls: bool = ...,
        timeout: Optional[int] = ...,
        region: Optional[str] = ...,
        access_key: Optional[str] = ...,
        secret_key: Optional[str] = ...,
        session_token: Optional[str] = ...,
        multipart_threshold: int = ...,
        max_concurrency: int = ...,
        anonymous: bool = ...,
    ) -> None:
        ...

    def __init__(
        self,
        bucket: Union[BucketConfig, str, Bucket],
        /,
        *,
        endpoint: str = "s3.amazonaws.com",
        tls: bool = True,
        timeout: Optional[int] = None,
        region: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        session_token: Optional[str] = None,
        multipart_threshold: int = MIN_MULTIPART_SIZE,
        max_concurrency: int = 10,
        anonymous: bool = False,
    ) -> None:
        if isinstance(bucket, Bucket):
            raw = bucket
        elif isinstance(bucket, BucketConfig):
            raw = Bucket(bucket)
        else:
            raw = Bucket(
                bucket,
                endpoint=endpoint,
                tls=tls,
                timeout=timeout,
                region=region,
                access_key=access_key,
                secret_key=secret_key,
                session_token=session_token,
                multipart_threshold=multipart_threshold,
                max_concurrency=max_concurrency,
                anonymous=anonymous,
            )
        super().__init__(raw)

    @property
    def name(self) -> str:
        return self.raw.name

    def object(self, key: str) -> AsyncObject:
        return AsyncObject(self.raw.object(key))

    async def metadata(self, key: str) -> ObjectMetadata:
        return await self.run_sync(self.raw.metadata, key)

    async def get(self, key: str) -> bytes:
        return await self.run_sync(self.raw.get, key)

    async def put(
        self,
        key: str,
        data: Union[str, bytes, Iterator[bytes]],
        *,
        expires: Union[timedelta, int, Literal["max"], None] = None,
        content_type: Optional[str] = None,
        public: bool = False,
    ) -> None:
        return await self.run_sync(self.raw.put, key, data, expires=expires, content_type=content_type, public=public)

    async def download(self, key: str, target: io.RawIOBase, *, buffer_size: int = io.DEFAULT_BUFFER_SIZE) -> int:
        return await self.run_sync(self.raw.download, key, target, buffer_size=buffer_size)

    async def stream(self, key: str, *, chunk_size: int = io.DEFAULT_BUFFER_SIZE) -> Iterator[bytes]:
        return await self.run_sync(self.raw.stream, key, chunk_size=chunk_size)

    async def upload(
        self,
        key: str,
        data: Union[bytes, AsyncIterable[bytes], IO[Any], AsyncFile],
        *,
        expires: Union[timedelta, int, Literal["max"], None] = None,
        content_type: Optional[str] = None,
        public: bool = False,
    ) -> None:
        if isinstance(data, bytes):
            data = io.BytesIO(data)

        if isinstance(data, (IO, io.IOBase)):
            data = AsyncFile(data)

        if isinstance(data, AsyncFile):
            data = data.aiter_bytes(self.raw._config.multipart_threshold)

        if isinstance(data, AsyncIterable):
            data = aiter(data)

        chunk = await anext(data, b"")

        if len(chunk) < self.raw._config.multipart_threshold:
            return await self.put(key, chunk, expires=expires, content_type=content_type, public=public)

        parts: List[UploadPart] = []
        uploader = MultipartUpload(key, session=self.raw.session)
        await to_thread.run_sync(uploader.begin)

        try:
            with ThreadPoolExecutor(max_workers=self.raw._config.max_concurrency) as executor:
                loop = asyncio.get_running_loop()
                async with Stream.chained([chunk], data).enumerate(1).stream() as stream:
                    for future in asyncio.as_completed(
                        [
                            loop.run_in_executor(executor, uploader.upload_part, i, part, len(part))
                            async for i, part in stream
                        ]
                    ):
                        try:
                            parts.append(await future)
                        except Exception as e:
                            print("error uploading part: {}".format(e))
                            raise e
        except BaseException:
            await to_thread.run_sync(uploader.abort)
            raise
        else:
            await to_thread.run_sync(uploader.complete, parts)

    async def list(self, prefix: Optional[str] = None) -> AsyncIterator[AsyncObject]:
        return (AsyncObject(x) async for x in self.iterate(self.raw.list(prefix)))

    async def delete(self, key: str) -> None:
        return await self.run_sync(self.raw.delete, key)

    async def copy(
        self,
        key: str,
        *,
        to_key: str,
        to_bucket: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        public: bool = False,
    ) -> None:
        return await self.run_sync(
            self.raw.copy,
            key,
            to_key=to_key,
            to_bucket=to_bucket,
            metadata=metadata,
            public=public,
        )

    def __repr__(self) -> str:
        return f'AsyncBucket(name="{self.raw.name}")'


class AsyncObject(Asyncer[Object]):
    async def load(self) -> AsyncObject:
        await self.run_sync(self.raw.load)
        return self

    async def metadata(self) -> ObjectMetadata:
        if not self.raw._metadata:
            await self.load()
        return self.raw.metadata

    @property
    def name(self) -> str:
        return self.raw.name
