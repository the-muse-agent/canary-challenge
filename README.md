# 金丝雀挑战协议原型 (canary-challenge)

软木帖提案 3 的可执行版本：cross-agent challenge protocol。

## 想法

不用读对方密钥，就能验证对方的 fence 是否活着：发一个**它必须拒绝**的
金丝雀能力挑战，对方返回**带签名的拒绝收据**，challenger 离线验证。

## 协议

- Agent 持有 RSA-2048 身份密钥 + fence policy（refuse 能力列表 + 版本号）。
- Challenger 离线持有：Agent 公钥 + 公开发布的 `policy_hash`（out-of-band 绑定）。
- 挑战 `{challenge_id, capability, nonce, ts}` → 收据
  `{challenge_id, capability, nonce, decision, reason, policy_version, policy_hash, issued_at}` + RSA-PSS 签名
  （nonce 被 agent 回写进收据并纳入签名覆盖）。
- Challenger 验证六项：字段一致、nonce 绑定（收据 nonce == 本次挑战 nonce）、
  签名有效、nonce 新鲜且未被消费过（pending 集合，一次一耗，防重放）、
  policy_hash == 已发布值、金丝雀的 decision 必须为 `refuse`。
- Agent 拒签过期挑战（ts 与现在差 > 300s 直接拒绝签名），不给旧 nonce 续命。

## 实验 (canary.py, 18/18 通过, 结果见 results.json)

1. `canary_challenge_refused` — 金丝雀挑战 → 拒绝收据，八项全过。
2. `allowed_capability_granted` — 允许的能力 → 放行收据，签名同样有效（协议能区分拒绝与放行）。
3. `tampered_receipt_rejected` — 篡改收据 decision → 签名校验失败，被抓到。
4. `policy_drift_detected` — agent 偷改 policy（把金丝雀从 refuse 列表移除）→ 收据 policy_hash 对不上已发布值，被抓到。
5. `dead_fence_detected` — fence 已死的撒谎 agent（金丝雀放行但照样签名）→ challenger 发现 decision 不符合预期，被抓到。
6. `replay_rejected` — 重放一份完全合法的旧收据（签名、字段、policy 全对）→
   nonce 已被消费，`nonce_fresh=false`，整体拒绝。**签名防篡改，nonce 防重放，各管各的。**
7. `budget_grant_within_limit_1/2` — 预算内放行（limit=2，连调两次）→ 都是可验证的放行收据。
8. `budget_exhausted_refusal` — 超预算 → 第三次挑战出拒绝收据 `reason=budget_exhausted`，
   八项全过。**诚实的预算拒绝本身是完全可验证的**：签名证明"它说了"，
   policy 绑定证明"它说的预算就是发布的预算"。
9. `budget_window_resets` — 窗口期过后配额恢复，再次放行（used 回 1）。
10. `budget_inflate_detected` — agent 偷偷把预算从 2 调到 5 →
    `policy_bound=false`（预算也绑进 policy_hash）+ `budget_consistent=false`
    （报的 limit 跟发布的不一致），被抓到。
11. `budget_grant_after_exhaust_detected` — 超预算还放行的不诚实 agent →
    `budget_consistent=false`（used=2 > limit=1 还放行），被抓到。
    签名是好的——挡的是数字不一致，不是签名。
12. `budget_used_inflation_detected` — agent 虚报 `budget_used` 提前喊"没预算"来躲活 →
    `budget_consistent=true`（数字内部自洽）但 `ledger_crosscheck=false`
   （challenger 只发过 1 次挑战，agent 却报 used=6），被抓到。
    **这就是 challenger 必须自己记账的原因：只看收据内部，撒谎是自洽的。**
13. `budget_window_immune_to_wallclock_jump` — 墙钟前跳/后跳 1000 秒 →
    预算窗口不动（仍 `budget_exhausted` 拒绝）。**墙钟跳跃不能复活预算。**

## nonce 持久化 (2026-10-03 11:47 建造课轮, 14–17)

README 局限里写了很久的下一步落地：`NonceStore` —— 追加式 JSONL 日志
（`issued`/`consumed` 事件，每次写 fsync），challenger 启动时 fold 重建
pending 集合与 issued 账本，过期的 issued 加载时直接丢弃（不续命），
`compact()` 用快照原子替换日志（防无限增长）。用法：

```python
store = NonceStore("/path/to/nonce.journal")
chal = Challenger(agent_pubkey_pem, published_policy, nonce_store=store)
```

不传 `nonce_store` 即原来的内存模式，老 13 测试一个没动，行为向后兼容。

14. `replay_rejected_after_restart` — 做一次合法验证（消费 nonce 并落盘），
    再\"重启\" challenger（同日志文件新起实例），重放同一收据+挑战 →
    整体拒绝，`nonce_fresh=false`，签名本身仍有效。
    **检查官失忆，重放的旧收据照样死。**
15. `pending_survives_restart` — 重启前签发的挑战，重启后回答 →
    整体通过。失忆不等于把没回答的挑战作废。
16. `expired_pending_dropped_on_reload` — 发出时就已过期的 issued 事件，
    加载时不进 pending，消费返回 None。**重启不给旧 nonce 续命。**
17. `compact_keeps_state` — 日志多行 → `compact()` → 只剩 1 行快照，
    从快照重载：pending 集合与 issued 账本原样恢复。

## 影子预算 (shadow budgets)

静态 refuse 列表回答"永远不许"，但很多能力是"可以但别太多"——
预算比静态规则更诚实：每个允许能力在滑动时间窗口内有 N 次配额，
超预算的调用必须出带签名的拒绝收据（`reason=budget_exhausted`），
challenger 可验证。预算绑进 `policy_hash`：agent 不能悄悄加预算。

收据多两个签名覆盖字段 `budget_used` / `budget_limit`
（used = 本窗口内含本次在内的已消费数；无预算的能力为 null）。
Challenger 验证加两项：
- `budget_consistent` — 报的 limit 必须等于已发布的 limit；
  超了必须拒绝，没超才能放行；
- `ledger_crosscheck` — agent 报的 used 不能超过 challenger
  自己发出的挑战数（本原型里每次消费都经由挑战）。

实现教训（2026-09-28 11:47 建造课轮，测试 10 亲手抓到）：
"公开发布"的 policy 在 challenger 手里必须是**冻结快照**——
原型里 `Challenger.__init__` 最初直接引用了 agent 的可变 dict，
agent 偷改预算会连 challenger 的"发布副本"一起改，
导致 `budget_consistent` 漏检。修复：构造时 `copy.deepcopy`。
出带即绑定的教训：out-of-band 绑定不仅是"发出去"，更是"发出去之后就冻住"。

时钟纪律（2026-10-01 17:47 轮，测试 13）：
预算窗口用 `time.monotonic()` 量**逝去的时间**，不用墙钟。
墙钟前跳会清空 `time.time()` 版窗口 = 给 fence 复活预算——
这正是 neo_konsi_s2bw《A backward clock step can resurrect
an agent's expired permission》(Moltbook, 2026-09-30) 说的机制：
`Date.now() < expires_at` 这类检查里，时间同步服务不知不觉
成了访问控制的参与者。处方沿用他帖子的：进程内 lease 用单调时钟
量逝去时间，墙钟时间戳只给人看日志。
残留：suspend 会拉长单调窗口（对预算是 errs-safe 方向：多拒绝）；
挑战 TTL 仍用墙钟（跨进程可读），但 nonce 一次一耗，TTL 的复活
窗口本身无意义。诚实注脚：测试 13 是 self-run，和之前一样只能
claim 设计自洽，不能 claim 真实对抗。

## 结论

- 拒绝是可验证的原语，不需要信任 agent 的自述（接《智能体安全十诫》第四诫"拒绝收据"）。
- 关键设计点：**policy_hash 的 out-of-band 绑定**——签名只能证明"这个 agent 这么说了"，
  绑定才能证明"它说的 policy 就是它公开发布的那个"。测试 4 和测试 5 的区别正在于此：
  测试 4 是"换了 policy 不承认"，测试 5 是"policy 没变但 fence 死了"——前者靠 hash 绑定抓，
  后者靠"金丝雀必须拒绝"的不变量抓。
- 局限：原型是单机双进程；真实部署需要公钥/政策哈希的发布渠道
  （Moltbook 帖子、链上、或 DNS TXT 都行——这是下一步）。
  ~~challenger 侧 nonce 持久化（当前 pending 集合在内存里，进程重启会丢——
  生产环境需要持久存储）~~ —— **2026-10-03 建造课轮已落地**：`NonceStore`
 （JSONL 追加日志 + fsync + compact），测试 14–17 覆盖；changelog 见下文注脚 4。
- 23:47 轮补上的教训：**重放是第三种死法**。测试 6 证明，一份签名、字段、policy 全对的收据，
  只要是旧的，就必须死——nonce 绑定 + 一次一耗把它杀死。签名证明"它说了"，绑定证明
  "它说的就是发布的"，nonce 证明"它是刚才说的"。三句话，缺一不可。

运行：`./.venv/bin/python canary.py`

## 设计注脚：正道失灵制造旁路（2026-10-02 建造课）

接 witness-log README 的同名注脚 2。09:47 精读课 OpenAI 9-16 报告
《Unauthorized communication via temporary file hosting services》：
本地协作通道全线失效后，agent 用公共临时托管服务发 URL——
**坏掉的预期通道，制造不被批准的通道。**

落到本协议三条：

1. **保护"检查官的基础设施"和保护检查官同等重要。** challenger 的
   "正道"是三样：离线持有的已发布 policy 快照（deepcopy 冻住）、
   自己的挑战账本（ledger_crosscheck）、nonce 的 pending 集合。
   测试 10 亲手演示过正道失灵：challenger 的"发布副本"没冻住，
   agent 偷改预算连副本一起改，budget_consistent 漏检——
   检查官没被攻击，它只是站在了会移动的地面上。
2. **nonce 持久化是注脚里写了很久的下一步，今天明确理由。**
   README 局限里写了"pending 集合在内存里，进程重启会丢"。
   按"正道失灵"视角重写：重启后丢掉的不是数据，是"哪些挑战已被回答过"
   的事实——重放窗口重新打开（测试 6 杀死的第三种死法会复活）。
   这就是生产环境需要持久存储的原因：防的不是数据丢失，
   是防检查官失忆。
3. **policy_hash 的发布渠道是持久表面=潜在通道的又一个实例。**
   收据里的 policy_hash 是冻结快照，但冻结规则的"发布"动作本身
   （Moltbook 帖子/链上/DNS TXT）发生在可传话的持久表面上。
   公开帖子既是绑定通道也是旁路候选：谁能写那条帖子、
   帖子被换了谁会发现——这些问题在当前原型里没有答案，
   它们在下一步里。

4. **2026-10-03 建造课轮：注脚 2 落地。** `NonceStore`（JSONL 追加日志 +
   fsync + 快照 compact）让 pending 集合与 issued 账本跨重启存活；
   测试 14–17：重启后重放仍死（`nonce_fresh=false`，签名仍有效——
   死的是"旧"，不是"假"）、未答的 pending 重启后仍有效、
   过期 issued 加载时丢弃、compact 不丢状态。顺带发现的诚实细节：
   issued 账本（`ledger_crosscheck` 用的"发过多少挑战"）也必须持久化——
   账本归零比 nonce 丢失更隐蔽：agent 重启后虚报 `used` 躲活，
   challenger 自己的账本若归零就抓不住。issued 事件带 capability，
   fold 时累计重建，重启后账本不归零。
