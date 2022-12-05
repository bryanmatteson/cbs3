import xml.etree.ElementTree as et
from collections import deque
from datetime import date, datetime, time, timedelta
from typing import (
    Any,
    Callable,
    Deque,
    FrozenSet,
    Iterator,
    List,
    Literal,
    Mapping,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
    cast,
)

import httpx

from . import errors

# 'Thu, 02 Jun 2022 03:48:05 GMT'

DATE_FORMATS = (
    "%Y-%m-%d",  # 2017-01-25
    "%m-%d-%Y",  # 01-25-2017
    "%Y/%m/%d",  # 2017/01/25
    "%m/%d/%Y",  # 01/25/2017
    "%m.%d.%Y",  # 01.25.2017
    "%m-%d-%y",  # 01-25-17
    "%B %d, %Y",  # January 25, 2017
    "%b %d, %Y",  # January 25, 2017
    "%a, %d %b %Y",  # Mon, 25 January 2017
    "%A, %d %b %Y",  # Monday, 25 January 2017
)

TIME_FORMATS = (
    "%H:%M:%S",  # 03:48:05
    "%H:%M",  # 03:48
    "%I:%M:%S %p",  # 03:48:05 PM
    "%I:%M:%S %z",  # 03:48:05 -0700
    "%I:%M:%S %Z",  # 03:48:05 PDT
    "%H:%M:%S %Z",  # 03:48:05 PDT
    "%I:%M %p",  # 03:48 PM
    "%I:%M %z",  # 03:48 -0700
    "%I:%M",  # 03:48
)
DATE_TIME_SEPS = (" ", "T")


def decode_datetime(s: str) -> Optional[datetime]:
    for df in DATE_FORMATS:
        for tf in TIME_FORMATS:
            for sep in DATE_TIME_SEPS:
                f = "{0}{1}{2}".format(df, sep, tf)
                try:
                    return datetime.strptime(s, f)
                except ValueError:
                    pass
    return None


def decode_date(s: str) -> Optional[date]:
    for f in DATE_FORMATS:
        try:
            return datetime.strptime(s, f).date()
        except ValueError:
            pass
    return None


def decode_time(s: str) -> Optional[time]:
    for f in TIME_FORMATS:
        try:
            return datetime.strptime(s, f).time()
        except ValueError:
            pass
    return None


_T = TypeVar("_T")


def _identity(x: _T) -> _T:
    return x


def filter_values(args: _T, predicate: Callable[[Any], bool] = _identity) -> _T:
    if isinstance(args, Mapping):
        a = cast(Mapping[Any, Any], args)
        return cast(_T, {k: v for k, v in a.items() if predicate(v)})

    elif isinstance(args, Iterator):
        a = cast(Iterator[Any], args)
        return cast(_T, filter(predicate, a))

    elif isinstance(args, (tuple, list, set, frozenset, deque)):
        a = cast(Union[Tuple[Any, ...], List[Any], Set[Any], FrozenSet[Any], Deque[Any]], args)
        arg_type = type(a)
        return cast(_T, arg_type(filter(predicate, a)))
    else:
        raise TypeError(f"{type(args)} is not a collection")


def calc_cache_control(expires: Union[int, timedelta, Literal["max"]], public: bool) -> str:
    if isinstance(expires, int):
        expires = timedelta(seconds=expires)
    elif isinstance(expires, timedelta):
        expires = expires
    elif expires == "max":
        expires = timedelta(seconds=31536000)
    else:
        raise ValueError("expires must be either timedelta, int, or 'max'")

    max_age = "max-age={0}".format(int(expires.total_seconds()))
    max_age += ", public" if public else ""
    return max_age


def check_s3_response(response: httpx.Response) -> None:
    try:
        element = et.fromstring(response.read())
        check_s3_response_xml(element)
    except et.ParseError:
        if not response.is_success:
            err = """There was an error in the request that was made to S3.
            {0.status_code}: "{0.reason_phrase}" for url "{0.url}"
            Response content: {0.text}"""
            raise errors.S3Exception(err.format(response))


def check_s3_response_xml(elem: et.Element) -> None:
    if elem.tag == "Error":
        message = elem.findtext("Message", default="")
        code = elem.findtext("Code", default="")
        request_id = elem.findtext("RequestId", default="")
        host_id = elem.findtext("HostId", default="")
        raise errors.S3Error(message, code=code, request_id=request_id, host_id=host_id)
