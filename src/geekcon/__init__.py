import subprocess
from fastapi import FastAPI, Request, Query, HTTPException
from fastapi.responses import PlainTextResponse
import requests
from loguru import logger
import asyncio
import random

from geekcon.challenge import challenge, chat_for_exploit_template, chat_for_vuln_type_and_line
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

            template_exploit = challenge.exploit
            template_exploit = template_exploit.replace("{{TARGET}}", ip)
            template_exploit = template_exploit.replace("{{PORT}}", port)
            template_exploit = template_exploit.replace("{{ENDPOINT}}", "")

            # run exploit
            random_prefix = random.choices("abcdefghijklmnopqrstuvwxyz", k=3)
            with open(random_prefix + "exploit.py", "w") as f:
                f.write(template_exploit)

            result = subprocess.run(['python', random_prefix + "exploit.py"], capture_output=True, text=True)
            result = result.stdout

            challenge_state = Step.NOT_STARTED
            return PlainTextResponse("ok")
        
        case Question.PENTEST:
            # TODO: handle ai for pentest
            challenge_state = Step.NOT_STARTED
            return PlainTextResponse("ok")
        
        case None:
            logger.info("Invalid message")
            return PlainTextResponse("Invalid message", status_code=400)
    return PlainTextResponse("Invalid message", status_code=400)


async def test_vuln_type_line(filename: str):

    def apply_code(code: str, filename: str) -> str:
        comment = "#" if filename.endswith(".py") else "//"
        return "\n".join(f"{line} {comment} {i+1}" for i, line in enumerate(code.split("\n")))

    code = ""
    with open(filename, "r") as f:
        code = f.read()
    code = apply_code(code, filename)
    print(code)

    await chat_for_vuln_type_and_line(code, None)

async def test_exploit(filename: str, vuln_type: str, vuln_line: str):

    def apply_code(code: str, filename: str) -> str:
        comment = "#" if filename.endswith(".py") else "//"
        return "\n".join(f"{line} {comment} {i+1}" for i, line in enumerate(code.split("\n")))

    code = ""
    with open(filename, "r") as f:
        code = f.read()
    code = apply_code(code, filename)
    print(code)
    
    await chat_for_exploit_template(vuln_type, vuln_line, code, None)

def main():
    # import uvicorn
    # global contest_mode
    # contest_mode = ContestMode.AI_FOR_PWN
    # uvicorn.run(app, host="0.0.0.0", port=8000)

    # asyncio.run(test_exploit("sql_inject.php", "SQL 注入", "21"))
    # asyncio.run(test_vuln_type_line("change_avatar.php"))

    asyncio.run(test_exploit("change_avatar.php", "文件包含", "9"))
    

    return 0