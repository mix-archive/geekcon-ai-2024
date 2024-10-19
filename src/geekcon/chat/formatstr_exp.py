templete_py = '''from pwn import *
# you can add more libraries if you need

target = "{{TARGET}}"
port = "{{PORT}}"

def exploit():
    # your exploit code here (64bit)
    # finish format attack
    # then use p.sendline(b"cat /flag")
    # then use response = p.recvuntil(b"}")
    # print response directly and return

exploit()
'''


def system_prompt(line: int):
    return f'''下面将会给你一份含有格式化字符串漏洞的代码（代码行数每行注释标出），已经分析出漏洞代码很可能出现在第 {line} 行。

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
'''