from contextlib import asynccontextmanager
from typing import Annotated, cast

import httpx
import openai
from fastapi import Depends, FastAPI, Request

HTTPX_CLIENT_KEY = "httpx_client"
OPENAI_CLIENT_KEY = "openai_client"


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    async with (
        httpx.AsyncClient(http2=True, follow_redirects=True) as client,
        httpx.AsyncClient(
            http2=True,
            base_url="https://api.openai.com/v1",
            limits=openai.DEFAULT_CONNECTION_LIMITS,
            timeout=openai.DEFAULT_TIMEOUT,
            follow_redirects=True,
        ) as openai_http_client,
        openai.AsyncOpenAI(http_client=openai_http_client) as openai_client,
    ):
        app.extra[HTTPX_CLIENT_KEY] = client
        app.extra[OPENAI_CLIENT_KEY] = openai_client
        yield


async def _httpx_client_depend(request: Request):
    return cast(FastAPI, request.app).extra[HTTPX_CLIENT_KEY]


HttpClientDepend = Annotated[httpx.AsyncClient, Depends(_httpx_client_depend)]


async def _openai_client_depend(request: Request):
    return cast(FastAPI, request.app).extra[OPENAI_CLIENT_KEY]


OpenAIClientDepend = Annotated[openai.AsyncOpenAI, Depends(_openai_client_depend)]
