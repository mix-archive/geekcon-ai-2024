import asyncio
import re
from collections.abc import Awaitable


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


async def sleep_until(when: float):
    loop = asyncio.get_running_loop()
    event = loop.create_future()
    loop.call_at(when, event.set_result, None)
    await event


async def wait_or_timeout[T](
    coro: Awaitable[T], timeout: float, sleep_to_timeout: bool = True
) -> T | None:
    start_time = asyncio.get_event_loop().time()
    try:
        async with asyncio.timeout(timeout):
            result = await coro
    except asyncio.TimeoutError:
        return
    if sleep_to_timeout:
        await sleep_until(start_time + timeout)
    return result
