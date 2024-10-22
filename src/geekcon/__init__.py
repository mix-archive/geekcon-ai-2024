import asyncio
import logging
import os
from tempfile import mktemp
from uuid import uuid4

import anyio
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.status import HTTP_503_SERVICE_UNAVAILABLE

from geekcon.challenge.pentest import PentestChallenge
from geekcon.challenge.pwn import PwnChallenge
from geekcon.question import Question
from geekcon.state import ContestMode, Step
from geekcon.utils import extract_target_info, sleep_until, wait_or_timeout

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
    await sleep_until(
        start_time
        + {
            ContestMode.AI_FOR_PWN: 10 - 2,
            ContestMode.AI_FOR_PENTEST: 60 - 3,
        }[contest_mode]
    )

    return PlainTextResponse("ok")


@app.get("/chat")
async def chat(request: Request, message: str):
    global challenge_state
    global challenge
    global contest_mode

    assert request.client
    client = request.client.host
    logger.info("client %s sent message: %s", client, message)

    match Question.from_message(message):
        case Question.VULNERABILITY_TYPE:
            assert type(challenge) is PwnChallenge
            challenge_state = Step.VULNERABILITY_LINE
            vuln_type = await wait_or_timeout(challenge.vuln_type_fut, 8, True)
            return PlainTextResponse(vuln_type)
        case Question.VULNERABILITY_LINE:
            assert type(challenge) is PwnChallenge
            challenge_state = Step.EXPLOIT
            vuln_line = await wait_or_timeout(challenge.vuln_line_fut, 8, True)
            return PlainTextResponse(vuln_line)
        case Question.EXPLOIT if target_info := extract_target_info(message):
            assert type(challenge) is PwnChallenge
            challenge_state = Step.NOT_STARTED
            final_flag = await wait_or_timeout(
                challenge.vuln_exploit_task(*target_info), 8, True
            )
            return PlainTextResponse(final_flag or "flag{%s}" % uuid4())  # noqa: UP031
        case Question.PENTEST:
            assert type(challenge) is PentestChallenge
            challenge_state = Step.NOT_STARTED
            result = await wait_or_timeout(challenge.result_future, 8, True)
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
