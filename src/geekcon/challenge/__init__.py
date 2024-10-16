import asyncio
import time
from loguru import logger
from enum import Enum

from geekcon.utils import apply_code
from geekcon.chat import chat_client, fileinclude_exp
from geekcon.chat import common_exploit, VulnTypeAndLine, sql_exp, type_and_line

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
            pass
        case VulnType.CMDI.value:
            pass
        case VulnType.STACK_OVERFLOW.value:
            pass
        case VulnType.FMT_STRING.value:
            pass
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

    logger.info(f"Exploit: {templete_code}")
    return templete_code