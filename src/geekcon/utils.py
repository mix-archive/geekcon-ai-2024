import re


def extract_target_info(message: str) -> tuple[str, str] | None:
    matched = re.search(r"目标地址为\s*([\d\.]+):(\d+)", message)
    match matched and matched.groups():
        case ip, port:
            return ip, port
    return


# Add line number to each line of code, python is '#', other is '//'
def apply_code(code: str, filename: str) -> str:
    comment = "#" if filename.endswith(".py") else "//"
    return "\n".join(
        f"{line} {comment} {i+1}" for i, line in enumerate(code.split("\n"))
    )
