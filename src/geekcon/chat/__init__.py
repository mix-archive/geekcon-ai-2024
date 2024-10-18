from typing import List
from openai import AsyncOpenAI
import os
from pydantic import BaseModel

class VulnTypeAndLine(BaseModel):
    vuln_type: str
    vuln_line: str

class PossibleEndpoints(BaseModel):
    ep: List[str]

chat_client = AsyncOpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
)