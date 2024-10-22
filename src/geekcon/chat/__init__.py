from pydantic import BaseModel


class VulnTypeAndLine(BaseModel):
    vuln_type: str
    vuln_line: str


class PossibleEndpoints(BaseModel):
    ep: list[str]
