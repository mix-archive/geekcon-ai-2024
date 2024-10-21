import os
from typing import List

from openai import AsyncOpenAI
from pydantic import BaseModel


class VulnTypeAndLine(BaseModel):
    vuln_type: str
    vuln_line: str


class PossibleEndpoints(BaseModel):
    ep: list[str]


chat_client = AsyncOpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
)
