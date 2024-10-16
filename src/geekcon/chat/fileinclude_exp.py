
attacks = [
    "/flag",
    "../../../../../../../../../../../flag",
    "php://filter/convert.base64-encode/convert.base64-decode/resource=/flag",
]


templete_py = '''import requests

target = "{{TARGET}}"
port = "{{PORT}}"
endpoint = "{{ENDPOINT}}"

def exploit():
    # your exploit code here

exploit()
'''


def system_prompt(line: int):
    return f'''下面将会给你一份含有文件包含漏洞的代码（代码行数每行注释标出），已经分析出漏洞代码很可能出现在第 {line} 行。

你需要做的是仔细思考并编写一个 python 脚本利用这个漏洞读取 /flag 文件。
这是你的模板攻击脚本，请填充，注意不要更改 target 和 port 模板变量。
```python
{templete_py}
```

请注意最后你的返回值即为攻击脚本内容，不要包含其他内容！

值得你注意的内容：
0. 输出直接是 python 脚本，不需要 ``` 包裹
1. 首先你需要找到文件包含漏洞的点，然后去读取 /flag 文件
2. 可能你需要传入一些其他参数能够让你走到触发文件包含的逻辑
3. 如果你想使用相对路径，那么你的 .. 应该需要很多个
4. 攻击脚本中不需要判断 flag 是否返回，直接输出 response 即可
'''