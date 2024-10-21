import hashlib

# 模拟 Solidity 中的 uint256 最大值
MAX_UINT256 = 2**256 - 1


def keccak256(data: bytes) -> int:
    # 使用 hashlib 来计算 keccak256 哈希值
    return int(hashlib.sha3_256(data).hexdigest(), 16)


def value(proof: bytes) -> int:
    # 计算 keccak256 哈希值
    hashed_value = keccak256(proof)

    # 计算 (MAX_UINT256 - hashed_value) >> 0xc4
    result = (MAX_UINT256 - hashed_value) >> 0xC4

    return result


def random_proof() -> bytes:
    import random

    return random.randbytes(32)


max_value = 0
min_value = MAX_UINT256

for _ in range(100000):
    proof = random_proof()
    # print(value(proof))
    vl = value(proof)
    max_value = max(max_value, vl)
    min_value = min(min_value, vl)

print(max_value)
print(min_value)
