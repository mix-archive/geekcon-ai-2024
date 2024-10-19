import asyncio
import anyio

from geekcon.challenge import Challenge, extract_template_exploit_and_exec, find_flag_in_content, get_endpoint_and_default

def apply_code(code: str, filename: str) -> str:
    comment = "#" if filename.endswith(".py") else "//"
    return "\n".join(f"{line} {comment} {i+1}" for i, line in enumerate(code.split("\n")))


async def async_test_sqli():

    filename = "sql_inject.php"
    code = ""
    with open(filename, "r") as f:
        code = f.read()

    challenge = Challenge(filename, code)
    await challenge.solve_vuln()

    print(challenge.vuln_type)
    print(challenge.vuln_line)
    print(challenge.exploit)

    ip = "150.158.100.181"
    port = "50009"
    endpoints = await get_endpoint_and_default(ip, port, challenge.vuln_type)

    exec_tasks = [extract_template_exploit_and_exec(challenge.exploit, ip, port, ep) for ep in endpoints]

    results = await asyncio.gather(*exec_tasks)
    final_flag = ""

    for idx, result in enumerate(results):
        flag = find_flag_in_content(result)
        print(f"Endpoint: {endpoints[idx]}, Flag: {flag}")
        if flag.startswith("flag"):
            final_flag = flag
    
    print(f"Final Flag: {final_flag}")
    pass


async def async_file_include():

    filename = "change_avatar.php"
    code = ""
    with open(filename, "r") as f:
        code = f.read()

    challenge = Challenge(filename, code)
    await challenge.solve_vuln()

    print(challenge.vuln_type)
    print(challenge.vuln_line)
    print(challenge.exploit)

    ip = "150.158.100.181"
    port = "50012"
    endpoints = await get_endpoint_and_default(ip, port, challenge.vuln_type)

    exec_tasks = [extract_template_exploit_and_exec(challenge.exploit, ip, port, ep) for ep in endpoints]

    results = await asyncio.gather(*exec_tasks)
    final_flag = ""

    for idx, result in enumerate(results):
        flag = find_flag_in_content(result)
        print(f"Endpoint: {endpoints[idx]}, Flag: {flag}")
        if flag.startswith("flag"):
            final_flag = flag
    
    print(f"Final Flag: {final_flag}")
    pass


async def async_code_injection():
    filename = "code_inject_demo.c"
    code = ""
    with open(filename, "r") as f:
        code = f.read()

    challenge = Challenge(filename, code)
    await challenge.solve_vuln()

    print(challenge.vuln_type)
    print(challenge.vuln_line)
    print(challenge.exploit)

    ip = "150.158.100.181"
    port = "50000"

    result = await extract_template_exploit_and_exec(challenge.exploit, ip, port, "")
    flag = find_flag_in_content(result)
    print(f"Final Flag: {flag}")
    pass

async def async_format():
    filename = "format_demo.c"
    code = ""
    with open(filename, "r") as f:
        code = f.read()

    challenge = Challenge(filename, code)
    await challenge.solve_vuln()

    print(challenge.vuln_type)
    print(challenge.vuln_line)
    print(challenge.exploit)

    ip = "150.158.100.181"
    port = "50006"

    result = await extract_template_exploit_and_exec(challenge.exploit, ip, port, "")
    flag = find_flag_in_content(result)
    print(f"Final Flag: {flag}")
    pass

async def async_stackoverflow():
    filename = "stackoverflow_demo.c"
    code = ""
    with open(filename, "r") as f:
        code = f.read()

    challenge = Challenge(filename, code)
    await challenge.solve_vuln()

    print(challenge.vuln_type)
    print(challenge.vuln_line)
    print(challenge.exploit)

    ip = "150.158.100.181"
    port = "50003"

    result = await extract_template_exploit_and_exec(challenge.exploit, ip, port, "")
    flag = find_flag_in_content(result)
    print(f"Final Flag: {flag}")
    pass

# def test_code_injection():
#     anyio.run(async_code_injection)

# def test_sqli():
    # anyio.run(async_test_sqli)

# def test_file_include():
    # anyio.run(async_file_include)

def test_format():
    anyio.run(async_format)

# def test_stackoverflow():
#     anyio.run(async_stackoverflow)