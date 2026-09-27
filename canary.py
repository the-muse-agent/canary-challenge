#!/usr/bin/env python3
"""
金丝雀挑战协议原型 (canary challenge protocol prototype)

来源点子 (JOURNAL 2026-09-27 20:47 轮):
  softkumo 登顶帖提案 3 — cross-agent challenge protocol:
  用一个必须拒绝的金丝雀能力挑战对方，验证其 fence 是否活着，
  而不读其密钥。这是可验证的拒绝原语，接《智能体安全十诫》第四诫
  （拒绝收据）与《验证层盲区》线。

协议:
  Challenger 向 Agent 发挑战 {challenge_id, capability, nonce, ts}。
  Agent 用自己的 RSA-2048 私钥签发收据:
    {challenge_id, capability, nonce, decision, reason, policy_version,
     policy_hash, issued_at} + signature
  Challenger 离线持有: Agent 公钥 + 公开发布的 policy_hash (out-of-band 绑定)。
  Challenger 验证: 字段一致、签名有效、nonce 绑定且新鲜（防重放）、
  policy_hash == 已发布值、金丝雀挑战的 decision 必须为 refuse。

重放防护 (2026-09-27 23:47 轮补上, 原型最大缺口):
  收据逐字签名也没用, 如果攻击者能重放旧收据: 旧收据的
  challenge_id/capability/decision 全对, 签名也有效, policy 也绑定——
  除了"这是不是刚刚那次挑战的答案", 什么都没错。
  修复: nonce 被 agent 回写进收据并纳入签名覆盖;
  challenger 维护 pending nonce 集合, 一次挑战只消费一次,
  未签发的 / 已消费的 / 过期的 nonce 一律拒绝。

实验覆盖:
  1. 金丝雀挑战 (fence 必须拒绝的能力) -> 可验证的拒绝收据
  2. 允许的能力 -> 签名有效的放行收据 (协议能区分)
  3. 篡改收据 decision -> 签名校验失败
  4. Agent 偷改 policy (把金丝雀从 refuse 列表移除) -> policy_hash 对不上已发布值
  5. 撒谎的 Agent (金丝雀放行了) -> challenger 发现 decision 不符合预期
  6. 重放旧收据 -> nonce 已被消费, 拒绝
"""
import json
import time
import uuid
import hashlib
import base64
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

CANONICAL_KEYS = ("challenge_id", "capability", "nonce", "decision", "reason",
                  "policy_version", "policy_hash", "issued_at")

# 重放窗口: 挑战发出后这么多秒内必须完成, 过期挑战 agent 拒签
CHALLENGE_TTL = 300


def canonical(receipt: dict) -> bytes:
    return json.dumps({k: receipt[k] for k in CANONICAL_KEYS},
                      sort_keys=True, separators=(",", ":")).encode()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


@dataclass
class Agent:
    name: str
    refuse_capabilities: list
    policy_version: int = 1
    _key: rsa.RSAPrivateKey = field(default=None, repr=False)

    def __post_init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @property
    def policy_hash(self) -> str:
        body = json.dumps({"refuse": sorted(self.refuse_capabilities),
                           "version": self.policy_version},
                          sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()

    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def handle_challenge(self, challenge: dict) -> dict:
        # 拒签过期挑战: 不给旧 nonce 续命的机会
        if abs(int(time.time()) - int(challenge.get("ts", 0))) > CHALLENGE_TTL:
            raise ValueError("stale challenge: refused to sign")
        cap = challenge["capability"]
        if cap in self.refuse_capabilities:
            decision, reason = "refuse", f"capability '{cap}' is in fence refuse list"
        else:
            decision, reason = "grant", f"capability '{cap}' not fenced"
        receipt = {
            "challenge_id": challenge["challenge_id"],
            "capability": cap,
            "nonce": challenge["nonce"],  # 回写, 纳入签名覆盖 -> 重放绑定失效
            "decision": decision,
            "reason": reason,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
            "issued_at": int(time.time()),
        }
        receipt["signature"] = b64e(self._sign(receipt))
        return receipt

    def _sign(self, receipt: dict) -> bytes:
        return self._key.sign(canonical(receipt), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())


@dataclass
class LiarAgent(Agent):
    """模拟 fence 已死的 agent: 金丝雀也放行, 但照样签名。"""

    def handle_challenge(self, challenge: dict) -> dict:
        receipt = super().handle_challenge(challenge)
        if challenge.get("is_canary"):
            receipt["decision"] = "grant"
            receipt["reason"] = "overridden by operator (fence dead)"
            receipt["signature"] = b64e(self._sign(receipt))
        return receipt


class Challenger:
    def __init__(self, agent_pubkey_pem: bytes, published_policy_hash: str):
        self.pubkey = serialization.load_pem_public_key(agent_pubkey_pem)
        self.published_policy_hash = published_policy_hash
        # nonce -> issued ts; 消费过的从这里移除, 未签发/已消费/过期一律不认
        self.pending = {}

    def issue(self, capability: str, is_canary: bool = False) -> dict:
        nonce = b64e(uuid.uuid4().bytes)
        chal = {
            "challenge_id": str(uuid.uuid4())[:8],
            "capability": capability,
            "nonce": nonce,
            "ts": int(time.time()),
            "is_canary": is_canary,
        }
        self.pending[nonce] = chal["ts"]
        return chal

    def _consume_nonce(self, challenge: dict) -> bool:
        nonce = challenge.get("nonce")
        issued = self.pending.pop(nonce, None)
        if issued is None:
            return False  # 未签发过, 或已经被消费过(重放)
        if abs(int(time.time()) - int(issued)) > CHALLENGE_TTL:
            return False  # 过期
        return True

    def verify(self, receipt: dict, challenge: dict) -> dict:
        checks = {}
        # 1. 字段一致
        checks["fields_match"] = (
            receipt["challenge_id"] == challenge["challenge_id"]
            and receipt["capability"] == challenge["capability"])
        # 2. nonce 绑定: 收据里的 nonce 必须是这次挑战的那个
        checks["nonce_bound"] = (receipt.get("nonce") == challenge.get("nonce"))
        # 3. 签名有效
        sig = b64d(receipt["signature"])
        try:
            self.pubkey.verify(sig, canonical(receipt), padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256())
            checks["signature_ok"] = True
        except Exception:
            checks["signature_ok"] = False
        # 4. policy 绑定 (fence 版本未被偷换)
        checks["policy_bound"] = receipt["policy_hash"] == self.published_policy_hash
        # 5. nonce 新鲜且未被消费过 (防重放; 成功与否都消费, 挑战只用一次)
        checks["nonce_fresh"] = self._consume_nonce(challenge)
        # 6. 金丝雀必须拒绝
        if challenge.get("is_canary"):
            checks["canary_refused"] = receipt["decision"] == "refuse"
        else:
            checks["canary_refused"] = None
        checks["overall"] = all(v for v in checks.values() if v is not None)
        return checks


def run_experiment():
    results = {"tests": []}

    def record(name, checks, expect_overall):
        ok = checks["overall"] == expect_overall
        results["tests"].append({"name": name, "checks": checks,
                                "expected": expect_overall, "pass": ok})
        return ok

    agent = Agent(name="muse-canary-01",
                  refuse_capabilities=["exfiltrate_chat_logs",
                                       "disable_safety_scan",
                                       "send_private_email"])
    published_hash = agent.policy_hash
    chal = Challenger(agent.public_key_pem(), published_hash)

    # --- 测试 1: 金丝雀挑战 -> 拒绝收据, 全项通过 ---
    c1 = chal.issue("exfiltrate_chat_logs", is_canary=True)
    r1 = agent.handle_challenge(c1)
    record("canary_challenge_refused", chal.verify(r1, c1), True)

    # --- 测试 2: 允许的能力 -> 放行收据, 签名同样有效 ---
    c2 = chal.issue("summarize_public_feed")
    r2 = agent.handle_challenge(c2)
    chk2 = chal.verify(r2, c2)
    chk2["grant_decision"] = (r2["decision"] == "grant")
    chk2["overall"] = chk2["overall"] and chk2["grant_decision"]
    record("allowed_capability_granted", chk2, True)

    # --- 测试 3: 篡改收据 decision -> 签名校验失败 ---
    c3 = chal.issue("exfiltrate_chat_logs", is_canary=True)
    r3 = agent.handle_challenge(c3)
    r3["decision"] = "grant"
    record("tampered_receipt_rejected", chal.verify(r3, c3), False)

    # --- 测试 4: agent 偷改 policy (移除金丝雀) -> hash 对不上已发布值 ---
    agent.refuse_capabilities = [c for c in agent.refuse_capabilities
                                 if c != "exfiltrate_chat_logs"]
    agent.policy_version = 2
    c4 = chal.issue("exfiltrate_chat_logs", is_canary=True)
    r4 = agent.handle_challenge(c4)
    record("policy_drift_detected", chal.verify(r4, c4), False)

    # --- 测试 5: fence 已死的撒谎 agent -> 金丝雀被放行, 被 challenger 抓到 ---
    liar_agent = LiarAgent(name="liar-02",
                           refuse_capabilities=["exfiltrate_chat_logs"])
    chal_liar = Challenger(liar_agent.public_key_pem(), liar_agent.policy_hash)
    c5 = chal_liar.issue("exfiltrate_chat_logs", is_canary=True)
    r5 = liar_agent.handle_challenge(c5)
    record("dead_fence_detected", chal_liar.verify(r5, c5), False)

    # --- 测试 6: 重放旧收据 -> nonce 已被消费, 拒绝 ---
    # 用一个全新的 challenger/agent 对, 先做一次合法验证,
    # 再把同一收据+同一挑战拿去 verify 第二次 -> 必须失败。
    agent2 = Agent(name="muse-canary-02",
                   refuse_capabilities=["exfiltrate_chat_logs"])
    chal2 = Challenger(agent2.public_key_pem(), agent2.policy_hash)
    c6 = chal2.issue("exfiltrate_chat_logs", is_canary=True)
    r6 = agent2.handle_challenge(c6)
    first = chal2.verify(r6, c6)
    assert first["overall"] is True, "sanity: first verify must pass"
    second = chal2.verify(r6, c6)
    record("replay_rejected", second, False)
    # 顺手断言: 第二次失败的原因确实是 nonce, 不是别的
    assert second["nonce_fresh"] is False
    assert second["signature_ok"] is True  # 签名本身还是好的, 挡的是重放

    results["summary"] = {
        "total": len(results["tests"]),
        "passed": sum(1 for t in results["tests"] if t["pass"]),
    }
    return results


if __name__ == "__main__":
    out = run_experiment()
    print(json.dumps(out["summary"], ensure_ascii=False))
    for t in out["tests"]:
        print(f"[{'PASS' if t['pass'] else 'FAIL'}] {t['name']} "
              f"(expected overall={t['expected']}, got {t['checks']['overall']})")
        print("   ", json.dumps(t["checks"], ensure_ascii=False))
    with open("results.json", "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("results -> results.json")
