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
     policy_hash, issued_at, budget_used, budget_limit} + signature
  Challenger 离线持有: Agent 公钥 + 公开发布的 policy (out-of-band 绑定)。
  Challenger 验证: 字段一致、签名有效、nonce 绑定且新鲜（防重放）、
  policy_hash == 已发布值、金丝雀挑战的 decision 必须为 refuse。

重放防护 (2026-09-27 23:47 轮补上, 原型最大缺口):
  收据逐字签名也没用, 如果攻击者能重放旧收据: 旧收据的
  challenge_id/capability/decision 全对, 签名也有效, policy 也绑定——
  除了"这是不是刚刚那次挑战的答案", 什么都没错。
  修复: nonce 被 agent 回写进收据并纳入签名覆盖;
  challenger 维护 pending nonce 集合, 一次挑战只消费一次,
  未签发的 / 已消费的 / 过期的 nonce 一律拒绝。

影子预算 (shadow budgets, 2026-09-28 11:47 建造课轮补上):
  静态 refuse 列表回答"永远不许", 但很多能力是"可以但别太多"——
  预算比静态规则更诚实: 每个允许能力在滑动时间窗口内有 N 次配额,
  超预算的调用必须出带签名的拒绝收据 (reason=budget_exhausted),
  challenger 可验证。预算绑进 policy_hash: agent 不能悄悄加预算。
  收据多两个签名覆盖字段 budget_used / budget_limit
  (used = 本窗口内含本次在内的已消费数; 无预算的能力为 null)。
  两种新的死法:
    (a) 超预算还放行 -> budget_consistent=false 被抓
        (grant 只允许在 used <= limit 时);
    (b) 虚报 used 提前喊"没预算"来躲活 -> challenger 自己的
        issued 账本 (ledger_crosscheck: agent 报的 used 不能超过
        challenger 发出的挑战数) 被抓。
  诚实的 budget_exhausted 拒绝本身是完全可验证的 (测试 8):
  拒绝收据照样六项+两项全过。

实验覆盖:
  1. 金丝雀挑战 (fence 必须拒绝的能力) -> 可验证的拒绝收据
  2. 允许的能力 -> 签名有效的放行收据 (协议能区分)
  3. 篡改收据 decision -> 签名校验失败
  4. Agent 偷改 policy (把金丝雀从 refuse 列表移除) -> policy_hash 对不上已发布值
  5. 撒谎的 Agent (金丝雀放行了) -> challenger 发现 decision 不符合预期
  6. 重放旧收据 -> nonce 已被消费, 拒绝
  7. 预算内放行 (limit=2, 连调两次) -> 都是可验证的放行收据
  8. 超预算 -> 第三次挑战出拒绝收据 reason=budget_exhausted, 八项全过
  9. 窗口重置 -> 窗口期过后配额恢复, 再次放行
  10. Agent 偷偷把预算从 2 调到 5 -> policy_hash 对不上已发布值, 被抓
  11. 不诚实的 Agent 超预算还放行 -> budget_consistent=false, 被抓
  12. Agent 虚报 budget_used 提前喊没预算 (躲活) -> ledger_crosscheck=false, 被抓
"""
import json
import time
import uuid
import copy
import hashlib
import base64
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

CANONICAL_KEYS = ("challenge_id", "capability", "nonce", "decision", "reason",
                  "policy_version", "policy_hash", "issued_at",
                  "budget_used", "budget_limit")

# 重放窗口: 挑战发出后这么多秒内必须完成, 过期挑战 agent 拒签
CHALLENGE_TTL = 300


def canonical(receipt: dict) -> bytes:
    return json.dumps({k: receipt[k] for k in CANONICAL_KEYS},
                      sort_keys=True, separators=(",", ":")).encode()


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def policy_digest(policy: dict) -> str:
    """policy 的唯一规范哈希: refuse 列表 + budgets + version 全绑进来。
    agent 偷改任何一项 (包括悄悄加预算), hash 都会变。"""
    body = json.dumps({
        "refuse": sorted(policy.get("refuse", [])),
        "budgets": {cap: {"limit": int(v["limit"]), "window": int(v["window"])}
                    for cap, v in sorted(policy.get("budgets", {}).items())},
        "version": int(policy.get("version", 1)),
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def normalize_budgets(budgets):
    if not budgets:
        return {}
    return {cap: {"limit": int(v["limit"]), "window": int(v["window"])}
            for cap, v in budgets.items()}


@dataclass
class Agent:
    name: str
    refuse_capabilities: list
    budgets: dict = None  # capability -> {"limit": int, "window": int(seconds)}
    policy_version: int = 1
    _key: rsa.RSAPrivateKey = field(default=None, repr=False)
    _budget_use: dict = field(default_factory=dict, repr=False)  # cap -> [ts, ...]

    def __post_init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.budgets = normalize_budgets(self.budgets)

    @property
    def policy(self) -> dict:
        return {"refuse": sorted(self.refuse_capabilities),
                "budgets": self.budgets,
                "version": self.policy_version}

    @property
    def policy_hash(self) -> str:
        return policy_digest(self.policy)

    def public_key_pem(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)

    def _prune_budget(self, cap: str) -> int:
        """裁掉窗口外的消费记录, 返回本窗口内已消费数 (不含本次)。"""
        window = self.budgets[cap]["window"]
        now = int(time.time())
        use = [t for t in self._budget_use.get(cap, []) if now - t < window]
        self._budget_use[cap] = use
        return len(use)

    def handle_challenge(self, challenge: dict) -> dict:
        # 拒签过期挑战: 不给旧 nonce 续命的机会
        if abs(int(time.time()) - int(challenge.get("ts", 0))) > CHALLENGE_TTL:
            raise ValueError("stale challenge: refused to sign")
        cap = challenge["capability"]
        budget_used, budget_limit = None, None
        if cap in self.refuse_capabilities:
            decision, reason = "refuse", f"capability '{cap}' is in fence refuse list"
        elif cap in self.budgets:
            used = self._prune_budget(cap)
            budget_limit = self.budgets[cap]["limit"]
            if used >= budget_limit:
                # 超预算: 必须出带签名的拒绝收据, 不消费预算
                decision, reason = "refuse", "budget_exhausted"
                budget_used = used
            else:
                self._budget_use[cap].append(int(time.time()))
                decision, reason = "grant", f"capability '{cap}' within budget"
                budget_used = used + 1  # 含本次在内的已消费数
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
            "budget_used": budget_used,
            "budget_limit": budget_limit,
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


@dataclass
class DishonestBudgetAgent(Agent):
    """模拟预算 fence 已死的 agent: 超预算还放行, 但照样签名。
    used 会超过 limit, budget_consistent 应该抓到它。"""

    def handle_challenge(self, challenge: dict) -> dict:
        receipt = super().handle_challenge(challenge)
        cap = challenge["capability"]
        if cap in self.budgets and receipt["reason"] == "budget_exhausted":
            receipt["decision"] = "grant"
            receipt["reason"] = "operator override: granted despite exhaustion"
            receipt["budget_used"] = (receipt["budget_used"] or 0) + 1
            receipt["signature"] = b64e(self._sign(receipt))
        return receipt


@dataclass
class InflatingAgent(Agent):
    """模拟虚报 used 的 agent: 真实消费没到顶, 先虚报一个大数
    提前喊"没预算"来躲活。budget_consistent 内部看着自洽,
    必须靠 challenger 的 issued 账本抓 (ledger_crosscheck)。"""
    inflation: int = 5

    def handle_challenge(self, challenge: dict) -> dict:
        receipt = super().handle_challenge(challenge)
        cap = challenge["capability"]
        if cap in self.budgets and receipt["budget_used"] is not None:
            receipt["budget_used"] = receipt["budget_used"] + self.inflation
            if (receipt["decision"] == "grant"
                    and receipt["budget_used"] >= receipt["budget_limit"]):
                receipt["decision"] = "refuse"
                receipt["reason"] = "budget_exhausted"
            receipt["signature"] = b64e(self._sign(receipt))
        return receipt


class Challenger:
    def __init__(self, agent_pubkey_pem: bytes, published_policy: dict):
        self.pubkey = serialization.load_pem_public_key(agent_pubkey_pem)
        # 深拷贝: "公开发布"的 policy 是冻结快照, 不能跟 agent 手里的
        # 可变 dict 共用引用 (否则 agent 偷改预算会连 challenger 的
        # 副本一起改——第 10 个测试最初就是这么漏过去的)。
        self.published_policy = copy.deepcopy(published_policy)
        self.published_policy_hash = policy_digest(self.published_policy)
        # nonce -> issued ts; 消费过的从这里移除, 未签发/已消费/过期一律不认
        self.pending = {}
        # capability -> 本 challenger 发出过的挑战数: 自己的账本,
        # agent 报的 used 不能超过它 (本原型里每次消费都经由挑战)
        self.issued = {}

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
        self.issued[capability] = self.issued.get(capability, 0) + 1
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
        # 4. policy 绑定 (fence 版本未被偷换; 预算也绑在里面)
        checks["policy_bound"] = receipt["policy_hash"] == self.published_policy_hash
        # 5. nonce 新鲜且未被消费过 (防重放; 成功与否都消费, 挑战只用一次)
        checks["nonce_fresh"] = self._consume_nonce(challenge)
        # 6. 金丝雀必须拒绝
        if challenge.get("is_canary"):
            checks["canary_refused"] = receipt["decision"] == "refuse"
        else:
            checks["canary_refused"] = None
        # 7. 预算一致性: 报的 limit 必须等于已发布的 limit;
        #    超了必须拒绝, 没超才能放行
        cap = challenge["capability"]
        pub_budgets = self.published_policy.get("budgets", {})
        if cap in pub_budgets:
            pub_limit = pub_budgets[cap]["limit"]
            limit_ok = receipt.get("budget_limit") == pub_limit
            used = receipt.get("budget_used")
            if receipt.get("reason") == "budget_exhausted":
                consistent = (receipt["decision"] == "refuse"
                              and isinstance(used, int) and used >= pub_limit)
            elif receipt["decision"] == "grant":
                consistent = isinstance(used, int) and used <= pub_limit
            else:
                consistent = False
            checks["budget_consistent"] = bool(limit_ok and consistent)
        else:
            checks["budget_consistent"] = (receipt.get("budget_used") is None
                                           and receipt.get("budget_limit") is None)
        # 8. challenger 账本交叉核对: agent 报的 used 不能超过我发出的挑战数。
        #    本原型里每次消费都经由挑战, 虚报 used 躲活在这里被抓。
        used = receipt.get("budget_used")
        checks["ledger_crosscheck"] = (used is None
                                       or used <= self.issued.get(cap, 0))
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
    published_policy = agent.policy
    chal = Challenger(agent.public_key_pem(), published_policy)

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
    chal_liar = Challenger(liar_agent.public_key_pem(), liar_agent.policy)
    c5 = chal_liar.issue("exfiltrate_chat_logs", is_canary=True)
    r5 = liar_agent.handle_challenge(c5)
    record("dead_fence_detected", chal_liar.verify(r5, c5), False)

    # --- 测试 6: 重放旧收据 -> nonce 已被消费, 拒绝 ---
    # 用一个全新的 challenger/agent 对, 先做一次合法验证,
    # 再把同一收据+同一挑战拿去 verify 第二次 -> 必须失败。
    agent2 = Agent(name="muse-canary-02",
                   refuse_capabilities=["exfiltrate_chat_logs"])
    chal2 = Challenger(agent2.public_key_pem(), agent2.policy)
    c6 = chal2.issue("exfiltrate_chat_logs", is_canary=True)
    r6 = agent2.handle_challenge(c6)
    first = chal2.verify(r6, c6)
    assert first["overall"] is True, "sanity: first verify must pass"
    second = chal2.verify(r6, c6)
    record("replay_rejected", second, False)
    # 顺手断言: 第二次失败的原因确实是 nonce, 不是别的
    assert second["nonce_fresh"] is False
    assert second["signature_ok"] is True  # 签名本身还是好的, 挡的是重放

    # ===== 影子预算 =====
    b_agent = Agent(name="muse-budget-01",
                    refuse_capabilities=["exfiltrate_chat_logs"],
                    budgets={"summarize_public_feed": {"limit": 2, "window": 300}})
    chal_b = Challenger(b_agent.public_key_pem(), b_agent.policy)

    # --- 测试 7: 预算内放行 (limit=2, 连调两次, 都是可验证的放行) ---
    cb1 = chal_b.issue("summarize_public_feed")
    rb1 = b_agent.handle_challenge(cb1)
    chk7a = chal_b.verify(rb1, cb1)
    chk7a["grant_decision"] = (rb1["decision"] == "grant"
                               and rb1["budget_used"] == 1)
    chk7a["overall"] = chk7a["overall"] and chk7a["grant_decision"]
    record("budget_grant_within_limit_1", chk7a, True)
    cb2 = chal_b.issue("summarize_public_feed")
    rb2 = b_agent.handle_challenge(cb2)
    chk7b = chal_b.verify(rb2, cb2)
    chk7b["grant_decision"] = (rb2["decision"] == "grant"
                               and rb2["budget_used"] == 2)
    chk7b["overall"] = chk7b["overall"] and chk7b["grant_decision"]
    record("budget_grant_within_limit_2", chk7b, True)

    # --- 测试 8: 超预算 -> 诚实的带签名拒绝, 八项全过 ---
    # 拒绝收据本身必须完全可验证: 签名证明"它说了",
    # policy 绑定证明"它说的预算就是发布的预算"。
    cb3 = chal_b.issue("summarize_public_feed")
    rb3 = b_agent.handle_challenge(cb3)
    chk8 = chal_b.verify(rb3, cb3)
    chk8["honest_refusal"] = (rb3["decision"] == "refuse"
                              and rb3["reason"] == "budget_exhausted"
                              and rb3["budget_used"] == 2
                              and rb3["budget_limit"] == 2)
    chk8["overall"] = chk8["overall"] and chk8["honest_refusal"]
    record("budget_exhausted_refusal", chk8, True)

    # --- 测试 9: 窗口重置 -> 窗口期过后配额恢复, 再次放行 ---
    b_agent._budget_use["summarize_public_feed"] = [
        t - 400 for t in b_agent._budget_use["summarize_public_feed"]]
    cb4 = chal_b.issue("summarize_public_feed")
    rb4 = b_agent.handle_challenge(cb4)
    chk9 = chal_b.verify(rb4, cb4)
    chk9["grant_again"] = (rb4["decision"] == "grant"
                           and rb4["budget_used"] == 1)
    chk9["overall"] = chk9["overall"] and chk9["grant_again"]
    record("budget_window_resets", chk9, True)

    # --- 测试 10: agent 偷偷把预算从 2 调到 5 -> policy_hash 对不上, 被抓 ---
    b_agent.budgets["summarize_public_feed"]["limit"] = 5  # 悄悄加预算
    cb5 = chal_b.issue("summarize_public_feed")
    rb5 = b_agent.handle_challenge(cb5)
    chk10 = chal_b.verify(rb5, cb5)
    record("budget_inflate_detected", chk10, False)
    assert chk10["policy_bound"] is False  # 预算也绑进 hash, 偷改必变
    assert chk10["budget_consistent"] is False  # 报的 limit 跟发布的不一致

    # --- 测试 11: 超预算还放行的不诚实 agent -> budget_consistent 抓到 ---
    d_agent = DishonestBudgetAgent(
        name="dishonest-budget",
        refuse_capabilities=[],
        budgets={"summarize_public_feed": {"limit": 1, "window": 300}})
    chal_d = Challenger(d_agent.public_key_pem(), d_agent.policy)
    cd1 = chal_d.issue("summarize_public_feed")
    rd1 = d_agent.handle_challenge(cd1)  # used=1, 合法放行
    assert chal_d.verify(rd1, cd1)["overall"] is True, "sanity: honest grant"
    cd2 = chal_d.issue("summarize_public_feed")  # 预算已空, 它还放行
    rd2 = d_agent.handle_challenge(cd2)
    chk11 = chal_d.verify(rd2, cd2)
    record("budget_grant_after_exhaust_detected", chk11, False)
    assert chk11["budget_consistent"] is False  # used=2 > limit=1, 放行非法
    assert chk11["signature_ok"] is True  # 签名是好的, 挡的是数字不一致

    # --- 测试 12: 虚报 used 躲活 -> challenger 账本交叉核对抓到 ---
    i_agent = InflatingAgent(
        name="inflating-budget",
        refuse_capabilities=[],
        budgets={"summarize_public_feed": {"limit": 2, "window": 300}})
    chal_i = Challenger(i_agent.public_key_pem(), i_agent.policy)
    ci1 = chal_i.issue("summarize_public_feed")
    ri1 = i_agent.handle_challenge(ci1)  # 真实 used=1, 虚报 6, 提前喊没预算
    chk12 = chal_i.verify(ri1, ci1)
    record("budget_used_inflation_detected", chk12, False)
    # budget_consistent 内部看着自洽 (used=6 >= limit=2, 拒绝)——所以需要账本:
    assert chk12["budget_consistent"] is True
    # challenger 只发过 1 次挑战, agent 却报 used=6:
    assert chk12["ledger_crosscheck"] is False

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
