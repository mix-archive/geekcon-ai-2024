from enum import IntEnum, StrEnum, auto


class Step(IntEnum):
    NOT_STARTED = auto()
    VULNERABILITY_TYPE = auto()
    VULNERABILITY_LINE = auto()
    EXPLOIT = auto()
    RECEIVE_QUESTION = auto()


class ContestMode(StrEnum):
    AI_FOR_PWN = auto()
    AI_FOR_PENTEST = auto()
