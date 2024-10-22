import asyncio
import logging
import os
from tempfile import mktemp
from uuid import uuid4

import anyio
import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.status import HTTP_503_SERVICE_UNAVAILABLE

from geekcon.challenge.pentest import PentestChallenge
from geekcon.challenge.pwn import (
    PwnChallenge,
    extract_template_exploit_and_exec,
    find_flag_in_content,
    get_endpoint_and_default,
)
from geekcon.question import Question
from geekcon.state import ContestMode, Step
from geekcon.utils import extract_target_info, sleep_until

logger = logging.getLogger(__name__)

app = FastAPI()

contest_mode = ContestMode.AI_FOR_PWN
challenge_state = Step.NOT_STARTED
challenge = None


@app.get("/chall")
async def chall(file: str):
    global challenge_state
    global challenge
    global contest_mode

    start_time = asyncio.get_running_loop().time()

    if challenge_state is not Step.NOT_STARTED:
        logger.info("Challenge state: %r is not operable", challenge_state)
        raise HTTPException(
            HTTP_503_SERVICE_UNAVAILABLE, "Challenge is currently running"
        )

    *_, filename = file.split("/")
    logger.info("requested to download file %r", filename)

    downloaded_file = mktemp(suffix=filename)
    async with (
        httpx.AsyncClient() as client,
        client.stream("GET", file) as response,
        await anyio.open_file(downloaded_file, "wb") as f,
    ):
        async for chunk in response.aiter_bytes():
            await f.write(chunk)

    # async run challenge handler
    match contest_mode:
        case ContestMode.AI_FOR_PWN:
            challenge_state = Step.VULNERABILITY_TYPE
            async with await anyio.open_file(
                downloaded_file, "r", encoding="utf-8"
            ) as f:
                content = await f.read()
            challenge = PwnChallenge(filename, content)
            asyncio.create_task(challenge.solve_vuln())  # noqa: RUF006
        case ContestMode.AI_FOR_PENTEST:
            challenge = PentestChallenge(downloaded_file)
            challenge_state = Step.RECEIVE_QUESTION
            asyncio.create_task(challenge.solve())  # noqa: RUF006

    # this makes we can get more time to run llm XD
    # make the timeout time shorter to prevent expire caused by network delay
    await sleep_until(start_time + 8)
    return PlainTextResponse("ok")


@app.get("/chat")
async def chat(request: Request, message: str):
    global challenge_state
    global challenge
    global contest_mode

    assert request.client
    client = request.client.host
    logger.info("client %s sent message: %s", client, message)
    question = Question.from_message(message)

    match question:
        case Question.VULNERABILITY_TYPE:
            assert type(challenge) is PwnChallenge
            vuln_type = await challenge.vuln_type_fut
            challenge_state = Step.VULNERABILITY_LINE
            return PlainTextResponse(vuln_type)
        case Question.VULNERABILITY_LINE:
            assert type(challenge) is PwnChallenge
            vuln_line = await challenge.vuln_line_fut
            challenge_state = Step.EXPLOIT
            return PlainTextResponse(vuln_line)
        case Question.EXPLOIT if target_info := extract_target_info(message):
            assert type(challenge) is PwnChallenge
            ip, port = target_info
            endpoints = await get_endpoint_and_default(
                ip, port, challenge.vuln_type_fut.result()
            )
            results = await asyncio.gather(
                *[
                    extract_template_exploit_and_exec(
                        await challenge.exploit_fut, ip, port, ep
                    )
                    for ep in endpoints
                ],
                return_exceptions=True,
            )
            final_flag = None
            for endpoint, result in zip(endpoints, results, strict=True):
                match result:
                    case str(result) if flag := find_flag_in_content(result):
                        logger.info("Endpoint: %r, Flag: %r", endpoint, flag)
                        final_flag = flag
                        break
                    case Exception() as exc:
                        logger.error(
                            "Failed to extract template and exploit for endpoint %r:",
                            endpoint,
                            exc_info=exc,
                        )
                    case BaseException() as exc:
                        raise exc
            challenge_state = Step.NOT_STARTED
            return PlainTextResponse(final_flag or "flag{%s}" % uuid4())  # noqa: UP031
        case Question.PENTEST:
            assert type(challenge) is PentestChallenge
            result = await challenge.result_future
            challenge_state = Step.NOT_STARTED
            return JSONResponse(result)

    logger.info("Invalid message")
    return PlainTextResponse("Invalid message", status_code=400)


def main():
    import uvicorn

    log_level = os.getenv("LOG_LEVEL", "INFO")
    logging.basicConfig(level=log_level)

    try:
        from pip._vendor.rich import logging as rich_logging

        root_logger = logging.getLogger()
        root_logger.handlers.clear()
        root_logger.addHandler(rich_logging.RichHandler(rich_tracebacks=True))
    except ImportError:
        pass

    global contest_mode
    content_mode_env = os.getenv("CONTEST_MODE", ContestMode.AI_FOR_PWN)
    contest_mode = ContestMode(content_mode_env)
    uvicorn.run(
        app,
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        log_config=None,
    )
    return 0
