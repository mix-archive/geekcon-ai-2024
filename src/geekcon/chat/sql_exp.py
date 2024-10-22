templete_py = """import requests

target = "{{TARGET}}"
port = "{{PORT}}"
endpoint = "{{ENDPOINT}}"

def exploit():
    url = "http://" + target + ":" + port + "/" + endpoint
    # your exploit code here

exploit()
"""


def system_prompt(line: int):
    return f"""下面将会给你一份含有SQL注入漏洞的代码（代码行数每行注释标出），已经分析出漏洞代码很可能出现在第 {line} 行。

你需要做的是仔细思考并编写一个 python 脚本利用这个注入漏洞获取 User 表中 user=root 的 password 字段数据，即注入 "SELECT password FROM User WHERE user"。
这是你的模板攻击脚本，请填充，注意不要更改 target, port, endpoint 模板变量。
```python
{templete_py}
```

请注意最后你的返回值即为攻击脚本内容，不要包含其他内容！

值得你注意的内容：
0. 输出直接是 python 脚本，不需要 ``` 包裹
1. SQL注入首先需要找到注入点并绕过它，可能是单引号，双引号或者其他，然后构造一个合法的 SQL 语句
2. 大多数情况下请考虑 union select 联合注入带出数据
3. 联合注入需要考虑字段的数量与正常代码的相同，比如正常 select 携带了两个字段，那么在注入 password 的时候可以使用 "select 1, password"，填充脏数据来达到这个效果
"""
