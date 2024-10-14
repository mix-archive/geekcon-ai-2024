import asyncio
import time
from loguru import logger
from enum import Enum

from geekcon.utils import apply_code
from geekcon.chat import chat_client
from geekcon.chat import vuln_type, vuln_line, common_exploit

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
    
    async def chat_for_vuln_type(self, code: str) -> str:
        completion = await chat_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "user", "content": vuln_type.prompt(code)}
            ],
        )
        result = completion.choices[0].message.content.strip()
        logger.info(f"Vulnerability type: {result}")
        return result
    
    async def chat_for_vuln_line(self, code: str) -> str:
        completion = await chat_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "user", "content": vuln_line.prompt(code)}
            ],
        )
        result = completion.choices[0].message.content.strip()
        logger.info(f"Vulnerability line: {result}")
        return result
    
    async def chat_for_exploit(self, code: str) -> str:
        
        line = int(self.vuln_line)

        # specific exploit for each vuln type
        match self.vuln_type:
            case VulnType.SQLI.value:
                
                completion = await chat_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "user", "content": common_exploit.prompt(code, self.vuln_type, line) }
                    ],
                )
                result = completion.choices[0].message.content.strip()
                logger.info(f"Exploit: {result}")
                with open("exploit.py", "w") as f:
                    f.write(result)
                pass
            case VulnType.CMDI:
                pass
            case VulnType.STACK_OVERFLOW:
                pass
            case VulnType.FMT_STRING:
                pass
            case VulnType.FILE_INCLUSION:
                pass

        return "TODO"

    async def solve_vuln(self):
        start_time = time.time()

        applied_code = apply_code(self.raw_code, self.filename)

        # 并行地执行三个问题

        self.vuln_type = await self.chat_for_vuln_type(applied_code)
        self.vuln_type_event.set()

        self.vuln_line = await self.chat_for_vuln_line(applied_code)
        self.vuln_line_event.set()

        self.exploit = await self.chat_for_exploit(applied_code)
        self.exploit_event.set()

        end_time = time.time()
        logger.info(f"Challenge finished in {end_time - start_time:.2f}s")

challenge: None | Challenge = None