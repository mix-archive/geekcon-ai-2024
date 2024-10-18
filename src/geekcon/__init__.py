import subprocess
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import PlainTextResponse
import requests
from loguru import logger
import asyncio
import random
import re

from geekcon.challenge import challenge, chat_for_exploit_template, chat_for_vuln_type_and_line, extract_template_exploit_and_exec, find_flag_in_content, get_endpoint_and_default
from geekcon.state import challenge_state, Step, contest_mode, ContestMode
from geekcon.challenge import Challenge
from geekcon.question import Question
from geekcon.utils import extract_target_info

app = FastAPI()

@app.get("/chall")
async def chall(request: Request, file: str = Query(...)):

    global challenge_state
    global challenge
    global contest_mode

    if challenge_state != Step.NOT_STARTED:
        logger.info(f"Challenge state: {challenge_state}")
        return PlainTextResponse("trying", status_code=400)

    filename = file.split("/")[-1]
    logger.info(f"requested to download file {filename}")

    try:
        response = requests.get(file, timeout=10)
        response.raise_for_status()
        content = response.text
    except Exception as e:
        logger.error(f"Failed to download file: {e}")
        raise HTTPException(status_code=400, detail="Failed to download file")
    
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

    client = request.client.host
    logger.info(f"{client} sent message: {message}")

    question = Question.from_message(message)

    match question:
        case Question.VULNERABILITY_TYPE:
            await challenge.vuln_type_event.wait()
            vuln_type = challenge.vuln_type
            challenge_state = Step.VULNERABILITY_LINE
            return PlainTextResponse(vuln_type)
        
        case Question.VULNERABILITY_LINE:
            await challenge.vuln_line_event.wait()
            vuln_line = challenge.vuln_line
            challenge_state = Step.EXPLOIT
            return PlainTextResponse(vuln_line)
        
        case Question.EXPLOIT:
            await challenge.exploit_event.wait()
            ip, port = extract_target_info(message)
            endpoints = await get_endpoint_and_default(ip, port, challenge.vuln_type)
            exec_tasks = [extract_template_exploit_and_exec(challenge.exploit, ip, port, ep) for ep in endpoints]

            results = await asyncio.gather(*exec_tasks)
            final_flag = ""

            for idx, result in enumerate(results):
                flag = find_flag_in_content(result)
                logger.info(f"Endpoint: {endpoints[idx]}, Flag: {flag}")
                if flag.startswith("flag"):
                    final_flag = flag

            challenge_state = Step.NOT_STARTED
            return PlainTextResponse(final_flag)
        
        case Question.PENTEST:
            # TODO: handle ai for pentest
            challenge_state = Step.NOT_STARTED
            return PlainTextResponse("ok")
        
        case None:
            logger.info("Invalid message")
            return PlainTextResponse("Invalid message", status_code=400)
    return PlainTextResponse("Invalid message", status_code=400)

def main():
    import uvicorn
    global contest_mode
    contest_mode = ContestMode.AI_FOR_PWN
    uvicorn.run(app, host="0.0.0.0", port=8000)
    return 0