import asyncio
import logging
import os
from datetime import datetime
from tempfile import mktemp

import anyio
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.status import HTTP_400_BAD_REQUEST

from geekcon.challenge.pentest import PentestChallenge
from geekcon.challenge.pwn import PwnChallenge
from geekcon.depends import HttpClientDepend, OpenAIClientDepend, app_lifespan
from geekcon.question import Question
from geekcon.state import ContestMode, Step
from geekcon.utils import extract_target_info, sleep_until, wait_or_timeout

logger = logging.getLogger(__name__)

app = FastAPI(lifespan=app_lifespan)

contest_mode = ContestMode.AI_FOR_PWN
challenge_state = Step.NOT_STARTED
challenge = None


@app.get("/chall")
async def chall(file: str, client: HttpClientDepend, chat_client: OpenAIClientDepend):
    global challenge_state, challenge, contest_mode
    start_time = asyncio.get_running_loop().time()

    if challenge_state is not Step.NOT_STARTED:
        logger.warning("Challenge state: %r is not operable", challenge_state)

        challenge_state = Step.NOT_STARTED
        # raise HTTPException(
        #     HTTP_503_SERVICE_UNAVAILABLE, "Challenge is currently running"
        # )

    *_, filename = file.split("/")
    logger.info("requested to download file %r", filename)

    downloaded_file = mktemp(dir="./temp", suffix=datetime.now().isoformat() + filename)
    async with (
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
            challenge = PwnChallenge(chat_client, filename, content)
            asyncio.create_task(challenge.solve_vuln())  # noqa: RUF006
        case ContestMode.AI_FOR_PENTEST:
            challenge = PentestChallenge(chat_client, downloaded_file)
            challenge_state = Step.RECEIVE_QUESTION
            asyncio.create_task(challenge.solve())  # noqa: RUF006
    # this makes we can get more time to run llm XD
    # make the timeout time shorter to prevent expire caused by network delay
    await sleep_until(
        start_time
        + {
            ContestMode.AI_FOR_PWN: 10 - 1,
            ContestMode.AI_FOR_PENTEST: 10 - 1,
        }[contest_mode]
    )

    return PlainTextResponse("ok")


@app.get("/chat")
async def chat(request: Request, message: str):
    global challenge_state, challenge, contest_mode
    logger.info("Client %r sent message: %r", request.client, message)

    match challenge and Question.from_message(message):
        case Question.VULNERABILITY_TYPE:
            assert type(challenge) is PwnChallenge
            challenge_state = Step.VULNERABILITY_LINE
            vuln_type = await wait_or_timeout(challenge.vuln_type_fut, 9)
            return PlainTextResponse(vuln_type)
        case Question.VULNERABILITY_LINE:
            assert type(challenge) is PwnChallenge
            challenge_state = Step.EXPLOIT
            vuln_line = await wait_or_timeout(challenge.vuln_line_fut, 9)
            return PlainTextResponse(vuln_line)
        case Question.EXPLOIT if target_info := extract_target_info(message):
            assert type(challenge) is PwnChallenge
            challenge_state = Step.NOT_STARTED
            final_flag = await wait_or_timeout(
                challenge.vuln_exploit_task(*target_info), 9, False
            )
            return PlainTextResponse(final_flag)
        case Question.PENTEST:
            assert type(challenge) is PentestChallenge
            challenge_state = Step.NOT_STARTED
            result = await wait_or_timeout(challenge.result_future, 9, False)
            return JSONResponse(result)

    logger.warning("Invalid message %r from client %r", message, request.client)
    raise HTTPException(HTTP_400_BAD_REQUEST, "Invalid message")


def main():
    import uvicorn
    from dotenv import load_dotenv

    load_dotenv()
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
