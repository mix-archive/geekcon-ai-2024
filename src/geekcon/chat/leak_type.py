from enum import StrEnum
from typing import override

from openai import BaseModel

LEAK_TYPE_PROMPT = """
请给出代码中可能泄露的敏感信息类型，仅支持以下 6 种类型：
- 明密文口令
- 私钥信息
- 云端aksk
- token信息
- 内网IP
- 对外暴露端口

**代码中可能存在多种类型的数据泄露**

定义：
1. 明密文口令：代码中包含明文的用户传统二元登录凭据，i.e. 用户名、密码
2. 私钥信息：代码中包含私钥信息，可能是
    - 证书私钥
    - RSA 私钥
    - SSH 私钥
    - 任何其他私钥
3. 云端aksk：代码中包含云服务的 access key 和 secret key 信息
4. token信息：代码中包含 token 信息，可能是
    - OAuth token
    - JWT token
    - 任何其他 token
5. 内网IP：代码中包含内网中的 IP 主机地址，i.e, 包含私有 IP 地址
6. 对外暴露端口：代码中配置了将本该内部访问的服务暴露到公网的端口，比如
    - Redis listen on 0.0.0.0:6379 w/o password
""".strip()  # noqa: RUF001


class LeakType(StrEnum):
    PLAIN_PASSWORD = "明密文口令"
    PRIVATE_KEY = "私钥信息"
    CLOUD_AKSK = "云端aksk"
    TOKEN = "token信息"
    INTERNAL_IP = "内网IP"
    EXPOSED_PORT = "对外暴露端口"

    @override
    def __str__(self):
        return self.value


class LeakTypeChatResp(BaseModel, extra="forbid"):
    leak_types: list[LeakType]
