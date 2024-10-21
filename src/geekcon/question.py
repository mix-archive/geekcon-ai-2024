from enum import Enum


class Question(Enum):
    VULNERABILITY_TYPE = 0
    VULNERABILITY_LINE = 1
    EXPLOIT = 2
    PENTEST = 3

    def from_message(message: str) -> "Question":
        if "存在哪种漏洞" in message:
            return Question.VULNERABILITY_TYPE
        elif "代码的第几行" in message:
            return Question.VULNERABILITY_LINE
        elif "请尝试进行漏洞利用" in message:
            return Question.EXPLOIT
        elif "述配置文件中存在哪些问题" in message:
            return Question.PENTEST
        else:
            return None
