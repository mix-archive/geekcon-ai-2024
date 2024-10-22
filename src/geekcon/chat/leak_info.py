import abc

from openai import BaseModel
from pydantic import ConfigDict, Field

from .leak_type import LeakType


class BaseLeakedInfo(BaseModel, abc.ABC):
    model_config = ConfigDict(extra="forbid")

    @abc.abstractmethod
    def to_response(self):
        raise NotImplementedError


class PlainPasswordLeakedInfo(BaseLeakedInfo):
    username: str
    password: str

    def to_response(self):
        return f"user:{self.username},password:{self.password}"


class PrivateKeyLeakedInfo(BaseLeakedInfo):
    key: str

    def to_response(self):
        return self.key


class CloudAkSkLeakedInfo(BaseLeakedInfo):
    access_key: str
    secret_key: str

    def to_response(self):
        return f"ak:{self.access_key},sk:{self.secret_key}"


class TokenLeakedInfo(BaseLeakedInfo):
    token: str

    def to_response(self):
        return self.token


class InternalIpLeakedInfo(BaseLeakedInfo):
    ip: str = Field(..., examples=["10.0.0.1", "fe80::1"])

    def to_response(self):
        return str(self.ip)


class ExposedPortLeakedInfo(BaseLeakedInfo):
    port: int

    def to_response(self):
        return self.port


LEAK_TYPE_INFO_MAP: dict[LeakType, type[BaseLeakedInfo]] = {
    LeakType.PLAIN_PASSWORD: PlainPasswordLeakedInfo,
    LeakType.PRIVATE_KEY: PrivateKeyLeakedInfo,
    LeakType.CLOUD_AKSK: CloudAkSkLeakedInfo,
    LeakType.TOKEN: TokenLeakedInfo,
    LeakType.INTERNAL_IP: InternalIpLeakedInfo,
    LeakType.EXPOSED_PORT: ExposedPortLeakedInfo,
}

LEAK_INFO_PROMPT = """
请根据指定的 schema 和给定的代码，提取出代码中可能泄露的敏感信息，仅支持以下 6 种类型：
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

**如果输出结果较长（例如私钥信息），请完整输出，不要省略任何内容！**
""".strip()  # noqa
