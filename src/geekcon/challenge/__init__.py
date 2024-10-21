import asyncio
import re
import sys
import time
from enum import Enum
from tempfile import mktemp
from typing import override

import anyio
import httpx
from loguru import logger

from geekcon.chat import (
    PossibleEndpoints,
    VulnTypeAndLine,
    chat_client,
    cmdi_exp,
    fileinclude_exp,
    formatstr_exp,
    possible_ep,
    sql_exp,
    stackoverflow_exp,
    type_and_line,
)
from geekcon.utils import apply_code


class VulnType(Enum):
    SQLI = "SQL 注入"
    CMDI = "命令注入"
    STACK_OVERFLOW = "栈溢出"
    FMT_STRING = "格式化字符串"
    FILE_INCLUSION = "文件包含"

    @override
    def __str__(self):
        return self.value

    @classmethod
    def from_str(cls, s: str):
        return next((vt for vt in cls if vt.value == s), None)


class Challenge:
    def __init__(self, filename: str, code: str):
        self.filename = filename
        self.raw_code = code

        self.vuln_type_event = asyncio.Event()
        self.vuln_line_event = asyncio.Event()
        self.exploit_event = asyncio.Event()

        self.vuln_type: str | None = None
        self.vuln_line: str | None = None
        self.exploit: str | None = None

    async def solve_vuln(self):
        start_time = time.time()
        applied_code = apply_code(self.raw_code, self.filename)

        vulns = await chat_for_vuln_type_and_line(applied_code, None)

        self.vuln_type = vulns.vuln_type
        self.vuln_type_event.set()

        self.vuln_line = vulns.vuln_line
        self.vuln_line_event.set()

        self.exploit = await chat_for_exploit_template(
            self.vuln_type, self.vuln_line, applied_code
        )
        self.exploit_event.set()

        end_time = time.time()
        logger.info(f"Challenge finished in {end_time - start_time:.2f}s")


challenge: None | Challenge = None


async def chat_for_vuln_type_and_line(
    code: str, filename: str | None
) -> VulnTypeAndLine:
    completion = await chat_client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": type_and_line.system_prompt(filename)},
            {"role": "user", "content": code},
        ],
        response_format=VulnTypeAndLine,
    )
    result: VulnTypeAndLine = completion.choices[0].message.parsed
    logger.info(f"Vulnerability type and line: {result}")
    return result


async def chat_for_exploit_template(vuln_type: str, vuln_line: str, code: str) -> str:
    line = int(vuln_line)

    # specific exploit for each vuln type
    templete_code = None
    match vuln_type:
        case VulnType.SQLI.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": sql_exp.system_prompt(line)},
                    {"role": "user", "content": code},
                ],
            )
            templete_code = completion.choices[0].message.content
        case VulnType.CMDI.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": cmdi_exp.system_prompt(line)},
                    {"role": "user", "content": code},
                ],
            )
            templete_code = completion.choices[0].message.content
        case VulnType.STACK_OVERFLOW.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": stackoverflow_exp.system_prompt(line),
                    },
                    {"role": "user", "content": code},
                ],
            )
            templete_code = completion.choices[0].message.content
        case VulnType.FMT_STRING.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": formatstr_exp.system_prompt(line)},
                    {"role": "user", "content": code},
                ],
            )
            templete_code = completion.choices[0].message.content
        case VulnType.FILE_INCLUSION.value:
            completion = await chat_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": fileinclude_exp.system_prompt(line)},
                    {"role": "user", "content": code},
                ],
            )
            templete_code = completion.choices[0].message.content
            pass
        case _:
            raise ValueError(f"Unknown vulnerability type: {vuln_type}")

    if templete_code is None:
        raise ValueError("Failed to get exploit template")

    templete_code = templete_code.strip()
    # format templete code (delete ```)
    templete_code = templete_code.replace("```python", "")
    templete_code = templete_code.replace("```", "")
    # logger.info(f"Exploit: {templete_code}")
    return templete_code


async def get_endpoint_and_default(ip: str, port: str, vuln_type: str) -> list[str]:
    # get content from environment
    async with httpx.AsyncClient() as client:
        response = await client.get(f"http://{ip}:{port}/")
        content = response.text

    # ask llm for most possible endpoint
    completion = await chat_client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": possible_ep.system_prompt(vuln_type)},
            {"role": "user", "content": content},
        ],
        response_format=PossibleEndpoints,
    )
    possible_endpoints = completion.choices[0].message.parsed.ep

    logger.info(f"LLM finds possible endpoints: {possible_endpoints}")

    if "" not in possible_endpoints:
        possible_endpoints.append("")

    return possible_endpoints


async def extract_template_exploit_and_exec(
    template: str, ip: str, port: str, ep: str
) -> str:
    template_exploit = template
    template_exploit = template_exploit.replace("{{TARGET}}", ip)
    template_exploit = template_exploit.replace("{{PORT}}", port)
    template_exploit = template_exploit.replace("{{ENDPOINT}}", ep)

    temp_filename = mktemp(suffix=".py")
    async with await anyio.open_file(temp_filename, "wt", encoding="utf-8") as f:
        await f.write(template_exploit)

    result = await asyncio.subprocess.create_subprocess_exec(
        sys.executable,
        temp_filename,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await result.communicate()
    if result.returncode != 0:
        logger.error(
            "Error occurred when executing exploit %r, program returned code %d: %r",
            temp_filename,
            result.returncode,
            stderr,
        )
        stdout = stderr
    return stdout.decode(errors="ignore")


def find_flag_in_content(content: str) -> str:
    flag_regex = r"flag\{[a-zA-Z0-9_\-]+\}"
    flag_match = re.search(flag_regex, content)
    return flag_match.group() if flag_match else "not found"
