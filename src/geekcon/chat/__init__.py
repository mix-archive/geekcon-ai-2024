import os

from dotenv import load_dotenv
from openai import AsyncOpenAI
from pydantic import BaseModel

load_dotenv()


class VulnTypeAndLine(BaseModel):
    vuln_type: str
    vuln_line: str


class PossibleEndpoints(BaseModel):
    ep: list[str]


chat_client = AsyncOpenAI(
    api_key=os.environ.get("OPENAI_API_KEY"),
)
