import asyncio

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from loguru import logger

from geekcon.challenge import (
    Challenge,
    extract_template_exploit_and_exec,
    find_flag_in_content,
    get_endpoint_and_default,
)
from geekcon.question import Question
from geekcon.state import ContestMode, Step
from geekcon.utils import extract_target_info

app = FastAPI()


@app.get("/chall")
async def chall(file: str):
    global challenge_state
    global challenge
    global contest_mode

    if challenge_state is not Step.NOT_STARTED:
        logger.info(f"Challenge state: {challenge_state}")
        return PlainTextResponse("trying", status_code=400)

    filename = file.split("/")[-1]
    logger.info(f"requested to download file {filename}")

    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(file, timeout=10)
            response.raise_for_status()
            content = response.text
        except Exception as e:
            logger.error(f"Failed to download file: {e}")
            raise HTTPException(
                status_code=400, detail="Failed to download file"
            ) from e

    # async run challenge handler
    challenge = Challenge(filename, content)

    match contest_mode:
        case ContestMode.AI_FOR_PWN:
            challenge_state = Step.VULNERABILITY_TYPE
            asyncio.create_task(challenge.solve_vuln())
        case ContestMode.AI_FOR_PENTEST:
            challenge_state = Step.RECEIVE_QUESTION
            # TODO

    # this makes we can get more time to run llm XD
    await asyncio.sleep(5)

    return PlainTextResponse("ok")


@app.get("/chat")
async def chat(request: Request, message: str = Query(...)):
    global challenge_state
    global challenge
    global contest_mode

    assert request.client
    client = request.client.host
    logger.info("client %s sent message: %s", client, message)
    question = Question.from_message(message)

    match question:
        case Question.VULNERABILITY_TYPE:
            vuln_type = await challenge.vuln_type_fut
            challenge_state = Step.VULNERABILITY_LINE
            return PlainTextResponse(vuln_type)
        case Question.VULNERABILITY_LINE:
            vuln_line = await challenge.vuln_line_fut
            challenge_state = Step.EXPLOIT
            return PlainTextResponse(vuln_line)
        case Question.EXPLOIT if target_info := extract_target_info(message):
            ip, port = target_info
            endpoints = await get_endpoint_and_default(
                ip, port, challenge.vuln_type_fut.result()
            )
            exec_tasks = [
                extract_template_exploit_and_exec(
                    await challenge.exploit_fut, ip, port, ep
                )
                for ep in endpoints
            ]

            results = await asyncio.gather(*exec_tasks)

            final_flag = None
            for idx, result in enumerate(results):
                flag = find_flag_in_content(result)
                logger.info(f"Endpoint: {endpoints[idx]}, Flag: {flag}")
                if flag is not None:
                    final_flag = flag
                    break

            challenge_state = Step.NOT_STARTED
            return PlainTextResponse(final_flag)
        case Question.PENTEST:
            # TODO: handle ai for pentest
            challenge_state = Step.NOT_STARTED
            return PlainTextResponse("ok")

    logger.info("Invalid message")
    return PlainTextResponse("Invalid message", status_code=400)


def main():
    import uvicorn

    global contest_mode
    contest_mode = ContestMode.AI_FOR_PWN
    uvicorn.run(app, host="0.0.0.0", port=8000)
    return 0
