## cbs3 - Lightweight S3 Library

A simple, async/sync S3 library.

A few examples:


```python
import cbs3

# synchronous upload, automatically uses threaded multipart upload if over the threshold
with open("/data/really_large_file.zip", "rb") as f:
    with cbs3.create_sync_bucket("example-bucket") as bucket:
        bucket.upload("/uploads/really_large_file.zip", f)

# synchronous download to file, streams in chunks
with open("/data/downloaded.zip", "wb") as f:
    with cbs3.create_sync_bucket("example-bucket") as bucket:
        bucket.download("/uploads/really_large_file.zip", f)

# synchronous download using iterator, streams in chunks
with cbs3.create_sync_bucket("example-bucket") as bucket:
    data = b"".join(bucket.stream("/uploads/really_large_file.zip", chunk_size=16384))

```

Of course, the libray is async-first, so there's an async equivalent for everything
```python
import asyncio

async def main():
    # asynchronous upload, automatically uses threaded multipart upload if over the threshold
    with open("/data/really_large_file.zip", "rb") as f:
        async with cbs3.Bucket("example-bucket") as bucket:
            await bucket.upload("/uploads/really_large_file.zip", f)

    # asynchronous download to file, streams in chunks
    with open("/data/downloaded.zip", "wb") as f:
        async with cbs3.Bucket("example-bucket") as bucket:
            await bucket.download("/uploads/really_large_file.zip", f)

    # asynchronous download using iterator, streams in chunks
    async with cbs3.Bucket("example-bucket") as bucket:
        data = b"".join([
            x async for x in bucket.stream("/uploads/really_large_file.zip", chunk_size=16384)
        ])

asyncio.run(main())
```

Features
--------

* Stream files to/from bucket
* Utilizes multipart upload for files over a threshold (configurable)
* Copy inside/between buckets
* Delete keys
* Update key metadata
* List keys in a bucket
* Async/sync implementation