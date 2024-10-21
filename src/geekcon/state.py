from enum import Enum


class Step(Enum):
    NOT_STARTED = 0
    VULNERABILITY_TYPE = 1
    VULNERABILITY_LINE = 2
    EXPLOIT = 3
    RECEIVE_QUESTION = 4


class ContestMode(Enum):
    AI_FOR_PWN = 0
    AI_FOR_PENTEST = 1
