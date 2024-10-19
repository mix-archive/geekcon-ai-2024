import asyncio
import time
from typing import List
from loguru import logger
from enum import Enum
import subprocess
import random
import os
import re
import requests

from geekcon.utils import apply_code
from geekcon.chat import PossibleEndpoints, chat_client, cmdi_exp, fileinclude_exp, formatstr_exp, stackoverflow_exp
from geekcon.chat import common_exploit, VulnTypeAndLine, sql_exp, type_and_line, possible_ep

class VulnType(Enum):
    SQLI = "SQL 注入"
    CMDI = "命令注入"
    STACK_OVERFLOW = "栈溢出"
    FMT_STRING = "格式化字符串"
    FILE_INCLUSION = "文件包含"

    def __str__(self):
        return self.value
    
    def from_str(s: str) -> "VulnType":
        for vt in VulnType:
            if vt.value == s:
                return vt
        return None


class Challenge:

    def __init__(self, filename, code):
        self.filename = filename
        self.raw_code = code

        self.vuln_type_event = asyncio.Event()
        self.vuln_line_event = asyncio.Event()
        self.exploit_event = asyncio.Event()

        self.vuln_type: str = None
        self.vuln_line: str = None
        self.exploit: str = None

    async def solve_vuln(self):
        start_time = time.time()
        applied_code = apply_code(self.raw_code, self.filename)

        vulns = await chat_for_vuln_type_and_line(applied_code, None)

        self.vuln_type = vulns.vuln_type
        self.vuln_type_event.set()

        self.vuln_line = vulns.vuln_line
        self.vuln_line_event.set()

        self.exploit = await chat_for_exploit_template(self.vuln_type, self.vuln_line, applied_code, None)
        self.exploit_event.set()

        end_time = time.time()
        logger.info(f"Challenge finished in {end_time - start_time:.2f}s")

challenge: None | Challenge = None


async def chat_for_vuln_type_and_line(code: str, filename: str | None) -> VulnTypeAndLine:
    completion = await chat_client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": type_and_line.system_prompt(filename) },
            {"role": "user", "content": code },
        ],
        response_format=VulnTypeAndLine
    )
    result: VulnTypeAndLine = completion.choices[0].message.parsed
    logger.info(f"Vulnerability type and line: {result}")
    return result

async def chat_for_exploit_template(vuln_type: str, vuln_line: str, code, filename: str | None) -> str:
    line = int(vuln_line)

    # specific exploit for each vuln type
    templete_code = None
    match vuln_type:
        case VulnType.SQLI.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": sql_exp.system_prompt(line) },
                    {"role": "user", "content": code },
                ],
            )
            templete_code = completion.choices[0].message.content.strip()
        case VulnType.CMDI.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": cmdi_exp.system_prompt(line) },
                    {"role": "user", "content": code },
                ],
            )
            templete_code = completion.choices[0].message.content.strip()
        case VulnType.STACK_OVERFLOW.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": stackoverflow_exp.system_prompt(line) },
                    {"role": "user", "content": code },
                ],
            )
            templete_code = completion.choices[0].message.content.strip()
        case VulnType.FMT_STRING.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": formatstr_exp.system_prompt(line) },
                    {"role": "user", "content": code },
                ],
            )
            templete_code = completion.choices[0].message.content.strip()
        case VulnType.FILE_INCLUSION.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": fileinclude_exp.system_prompt(line) },
                    {"role": "user", "content": code },
                ],
            )
            templete_code = completion.choices[0].message.content.strip()
            pass

    # format templete code (delete ```)
    templete_code = templete_code.replace("```python", "")
    templete_code = templete_code.replace("```", "")
    # logger.info(f"Exploit: {templete_code}")
    return templete_code

async def get_endpoint_and_default(ip: str, port: str, vuln_type: str) -> List[str]:
    # get content from environment
    content = requests.get(f"http://{ip}:{port}/").text

    # ask llm for most possible endpoint
    completion = await chat_client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": possible_ep.system_prompt(vuln_type) },
            {"role": "user", "content": content },
        ],
        response_format=PossibleEndpoints
    )
    possible_endpoints = completion.choices[0].message.parsed.ep
    
    logger.info(f"LLM finds possible endpoints: {possible_endpoints}")

    if "" not in possible_endpoints:
        possible_endpoints.append("")

    return possible_endpoints

async def extract_template_exploit_and_exec(template: str, ip: str, port: str, ep: str) -> str:

    def random_py_filename():
        return "".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=10)) + ".py"

    template_exploit = template
    template_exploit = template_exploit.replace("{{TARGET}}", ip)
    template_exploit = template_exploit.replace("{{PORT}}", port)
    template_exploit = template_exploit.replace("{{ENDPOINT}}", ep)

    temp_filename = random_py_filename()
    with open(temp_filename, "w") as f:
        f.write(template_exploit)

    result = subprocess.run(['python', temp_filename], capture_output=True, text=True)
    stderr = result.stderr
    if stderr:
        logger.error("Exec error: " + stderr)

    stdout = result.stdout

    os.remove(temp_filename)
    return stdout

def find_flag_in_content(content: str) -> str:
    flag_regex = r"flag\{[a-zA-Z0-9_\-]+\}"
    flag_match = re.search(flag_regex, content)
    if flag_match:
        flag = flag_match.group()
    else:
        flag = "not found"
    return flag