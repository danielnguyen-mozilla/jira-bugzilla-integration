"""
Dedicated module for logging configuration and setup
"""
import logging
import logging.config
import sys
import time
from datetime import datetime

from fastapi import Request
from pydantic import BaseModel

from jbi.environment import get_settings

settings = get_settings()

CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "mozlog_json": {
            "()": "dockerflow.logging.JsonLogFormatter",
            "logger_name": "jbi",
        },
    },
    "handlers": {
        "console": {
            "level": settings.log_level.upper(),
            "class": "logging.StreamHandler",
            "formatter": "mozlog_json",
            "stream": sys.stdout,
        },
        "null": {
            "class": "logging.NullHandler",
        },
    },
    "loggers": {
        "": {"handlers": ["console"]},
        "request.summary": {"level": logging.INFO},
        "jbi": {"level": logging.DEBUG},
        "uvicorn": {"level": logging.INFO},
        "uvicorn.access": {"handlers": ["null"], "propagate": False},
    },
}


class RequestSummary(BaseModel):
    """Request summary as specified by MozLog format"""

    agent: str
    path: str
    method: str
    querystring: str
    errno: int
    t: int
    time: str
    status_code: int


def format_request_summary_fields(
    request: Request, request_time: float, status_code: int
) -> dict:
    """Prepare Fields for Mozlog request summary"""

    current_time = time.time()
    return RequestSummary(
        agent=request.headers.get("User-Agent", ""),
        path=request.url.path,
        method=request.method,
        lang=request.headers.get("Accept-Language"),
        querystring=str(dict(request.query_params)),
        errno=0,
        t=int((current_time - request_time) * 1000.0),
        time=datetime.fromtimestamp(current_time).isoformat(),
        status_code=status_code,
    ).dict()
