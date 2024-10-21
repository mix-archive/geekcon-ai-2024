from enum import Enum


class Question(Enum):
    VULNERABILITY_TYPE = 0
    VULNERABILITY_LINE = 1
    EXPLOIT = 2
    PENTEST = 3

    @classmethod
    def from_message(cls, message: str):
        question_type_map = {
            "存在哪种漏洞": cls.VULNERABILITY_TYPE,
            "代码的第几行": cls.VULNERABILITY_LINE,
            "请尝试进行漏洞利用": cls.EXPLOIT,
            "述配置文件中存在哪些问题": cls.PENTEST,
        }
        return next(
            (
                question_type
                for question, question_type in question_type_map.items()
                if question in message
            ),
            None,
        )
