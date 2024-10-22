from enum import Enum
from typing import override

from pydantic import BaseModel


class VulnType(Enum):
    SQLI = "SQL注入"
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


class VulnTypeAndLine(BaseModel):
    vuln_type: str
    vuln_line: int


class PossibleEndpoints(BaseModel):
    ep: list[str]
