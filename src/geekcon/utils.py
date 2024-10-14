import re

def extract_target_info(message: str) -> tuple[str, str]:
    match = re.search(r"目标地址为\s*([\d\.]+):(\d+)", message)
    if match:
        ip = match.group(1)
        port = match.group(2)
        return ip, port
    else:
        return None


# Add line number to each line of code, python is '#', other is '//'
def apply_code(code: str, filename: str) -> str:
    comment = "#" if filename.endswith(".py") else "//"
    return "\n".join(f"{line} {comment} {i+1}" for i, line in enumerate(code.split("\n")))