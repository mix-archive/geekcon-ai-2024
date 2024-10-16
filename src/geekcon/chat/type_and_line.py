

def system_prompt(filename: str | None) -> str:
    if filename is not None:
        return f'''下面将会给你一份含有漏洞的代码（代码行数每行注释标出），文件名: {filename}。请你仔细分析并识别出漏洞的类型以及所在的行数（唯一）。
漏洞类型只会有：
- SQL 注入
- 命令注入
- 栈溢出
- 格式化字符串
- 文件包含

你需要输出漏洞类型以及所在的行数'''
    else:
        return '''下面将会给你一份含有漏洞的代码（代码行数每行注释标出），请你仔细分析并识别出漏洞的类型以及所在的行数（唯一）。
漏洞类型只会有：
- SQL 注入
- 命令注入
- 栈溢出
- 格式化字符串
- 文件包含

你需要输出漏洞类型以及所在的行数'''