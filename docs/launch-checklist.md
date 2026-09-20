# Shadow Agent 上线检查清单

发布到生产环境前的逐项确认。全部勾选前不应对外提供服务。

## 1. 密钥与配置（阻断项）

- [ ] `SHADOW_AGENT_JWT_SECRET` 已设置（≥32 字符随机值），且未写入代码库/git
- [ ] `SHADOW_AGENT_API_KEY_PEPPER` 与 JWT 密钥是不同的随机值
- [ ] `SHADOW_AGENT_ADMIN_API_KEY` / `SHADOW_AGENT_CLIENT_API_KEY` 为高强度随机值，仅存于密钥管理设施
- [ ] `SHADOW_AGENT_CONSOLE_BOOTSTRAP_TOKEN` 已设置；首个管理员注册后妥善销毁记录
- [ ] `SHADOW_AGENT_ALLOW_OPEN_CONSOLE_BOOTSTRAP=false`（除非临时演示）
- [ ] `SHADOW_AGENT_ALLOW_SIMULATED_RESPONSES=false`（生产必须走真实上游）
- [ ] `SHADOW_AGENT_ALLOWED_ORIGINS` 仅包含真实控制台域名
- [ ] `.env` 文件不在镜像内（`.dockerignore` 已覆盖，构建后再核对）
- [ ] 所有默认密钥/演示密钥已轮换或删除

## 2. 部署架构

- [ ] 入口已启用 TLS（反代/负载均衡终止），HTTP 明文端口未对外暴露
- [ ] 数据库卷启用静态加密并有备份策略
- [ ] 单实例部署：容器以非 root 用户运行，healthcheck 通过
- [ ] 多实例部署：`INSTALL_REDIS=true` 构建 + `SHADOW_AGENT_REDIS_URL` 已配置，且 `/health` 返回 `"shared_state": "redis"`
- [ ] 上游 LLM 提供商的 API key 仅存在于后端环境，从未下发到前端
- [ ] Alembic 迁移在部署流程中执行（容器入口已内置）

## 3. 安全验证

- [ ] `python -m pytest tests` 全部通过（含共享态测试）
- [ ] 未授权访问 `/metrics`、`/api/v1/logs` 返回 401/403
- [ ] 注入攻击样本（直接/间接/多轮）均被 403 阻断且有拦截日志
- [ ] `GET /api/v1/semantic-status`（管理员凭证）返回 `model_loaded: true`，`mode` 与灰度决策一致（建议先 `monitor` 观察再切 `enforce`）
- [ ] `GET /api/v1/rules/dlp-status` 确认响应侧 DLP 模式符合预期（生产建议 `redact` 或 `block`，不要 `off`）
- [ ] 中文注入改写样本人工抽测（已知短板：中文泛化召回低，见 [benchmarks/injection-detection.md](benchmarks/injection-detection.md)；monitor 模式事件可作回流标注）
- [ ] 登录连续失败触发账户锁定（429）
- [ ] 停用账户后其 JWT 立即失效
- [ ] 审批单二次审批返回 409（状态机完整）
- [ ] `python tools/check_openai_compat.py` 退出码为 0（网关对标准 OpenAI 请求/工具调用为 drop-in 兼容）
- [ ] 已按业务决定 `SHADOW_AGENT_UNKNOWN_TOOL_POLICY`：默认 `deny` 为严格白名单，
      **未在策略表中的第三方工具会被拒绝**；接入真实 Agent（工具名不可穷举）时需设为 `allow`，
      此时仍由行为风险引擎拦截危险命令/敏感文件/内网目标/凭据访问
- [ ] 已用真实客户端（含 function calling 多轮）人工跑通一次工具调用闭环
- [ ] 多租户隔离抽测：A 组织管理员按 id 访问/修改 B 组织的规则、密钥、日志均返回 404；SSE 事件流仅含本组织事件
- [ ] SSO 回调校验：错误 state / 过期 state 重放被拒绝（`#error=sso_invalid_state`）；停用账号在回调时被拒绝
- [ ] 若启用 SSO：`SHADOW_AGENT_CONSOLE_URL` / `SHADOW_AGENT_PUBLIC_BASE_URL` 为生产域名，IdP 侧已注册 `{PUBLIC_BASE_URL}/api/v1/auth/sso/callback` 回调地址，JIT 默认角色与邀请策略经过评审
- [ ] 无任何测试后门/调试端点残留（`/docs`、`/redoc` 视需要经反代屏蔽）

## 4. 可观测性与运维

- [ ] Prometheus 已抓取 `/metrics`（管理员凭证），告警规则覆盖 5xx 比率、延迟 P99、限流触发量
- [ ] 日志外送集中系统（审计防篡改）
- [ ] **网关进程的 stdout/stderr 必须被持续消费**（阻断项）：网关在事件循环线程上同步打日志，
  管道缓冲区写满（Windows 实测约 4KB）会让**整个进程静默停摆** —— 所有请求挂起、零字节返回、
  且不报任何错（卡住的就是日志本身）。禁止用「无人读取的管道」启动：`subprocess.PIPE` 无读线程、
  supervisor/journald 停止读取、重定向到已写满的磁盘、NSSM 等包装器丢弃输出等。
- [ ] 日志保留期已按 [gdpr.md](compliance/gdpr.md) 第 5 节决策并设置 `SHADOW_AGENT_*_RETENTION_DAYS` 环境变量（内置自动清理，默认拦截/告警/重放 180 天、审计 365 天）
- [ ] `/metrics` 中 `shadow_agent_retention_purged_rows_total` 已纳入监控（首次大额清理属预期行为）
- [ ] 备份恢复演练至少完成一次
- [ ] Redis 故障时的 fail-open 降级行为已纳入应急预案（限流退化为单实例）

## 5. 合规

- [ ] 面向欧盟：GDPR 数据映射与告知文本完成（见 [gdpr.md](compliance/gdpr.md)）
- [ ] 面向中国境内：等保定级备案与自查表完成（见 [mlps-2.0.md](compliance/mlps-2.0.md)）
- [ ] 与上游 LLM 提供商签署数据处理协议
- [ ] 工具拦截策略（黑名单/工具权限）已按业务场景评审

## 6. 性能验收

**绝对 rps 不是通过/不通过的门槛。** 同代码在同一台机器上背靠背复测差异 ≤10%，
但**跨会话（机器负载不同）实测差 13–20%**：2026-09-20 较早一次测得
health 841 / chat 294 / injection 152 / analyze 357 / logs 499 rps，
当日晚些时候用**同一份代码**（含 `git archive HEAD` 提取的纯提交版本）复测得下表数值；
`HEAD` 与工作树逐场景差异为 +3.0% / −2.3% / +4.5% / +3.4% / +13.2%（`logs` 一项落在
会话内噪声带内，见下），**未提交改动不构成性能回退**。因此下表的用途是**量级参考**，
验收以下面的相对判据为准，上线前必须在目标硬件上重测。

测量条件（缺任意一项，测得的数字无效）：

- `c=8`、每场景 15s；服务端 `stdout/stderr` 必须被消费（`DEVNULL` 或读线程）
- **两个限流变量都要抬高**：`SHADOW_AGENT_RATE_LIMIT_PER_MINUTE`
  **和** `SHADOW_AGENT_LOG_RATE_LIMIT_PER_MINUTE`（后者默认 20/min，只作用于
  `/api/v1/logs`；漏设会让 `logs` 场景测到 429 而不是吞吐，且不会报错）
- `SHADOW_AGENT_UPSTREAM_BASE_URL=" "`：dotenv 不覆盖已存在的环境变量，
  而 `backend/.env` 指向真实上游；漏设会让 `chat` 场景真的外发并返回 502
- loopback 目标须忽略环境代理（`perf/load_test.py` 已内建）

| 场景 | 实测区间 rps | p50 | p95 | 说明 |
| --- | ---: | ---: | ---: | --- |
| GET /health | 728–732 | 9.3 | 15–16 | 无认证、无 DB 写 |
| POST /chat/completions（放行） | 251 | 29.5–30.0 | 41.5–41.9 | 全检测引擎 |
| POST /chat/completions（阻断） | 134–144 | 44–49 | 109–112 | 含拦截日志写入 |
| POST /analyze | 285–314 | 24–26 | 34–39 | 无写 |
| GET /api/v1/logs（管理员） | 464–498 | 11 | 39–45 | 独立限流，见上 |
| mixed（9 场景 × c=8 = 72 worker） | 145–166 | 289–319 | 1218–1388 | **不与单场景行可比**，见下 |

两次运行合计 31,410 / 32,213 请求、**0 个 5xx**，压测后 `/health` 均为 200。

验收判据（相对，与硬件无关）：

- 阻断路径 p95 不劣化放行路径 3 倍以上（当前 109–112ms vs 41.5–41.9ms ≈ **2.6–2.7×**，通过）
- 语义检测层 p95 < 33ms（层内预算，与端到端请求延迟是两码事）
- 0 个 5xx，且压测后 `/health` 正常

⚠️ **`mixed` 行不与单场景行可比** —— 它展开成 9 个场景 × `--concurrency`，
即 `c=8` 时是 **72 路并发**，而单场景行只有 8 路。实测（同服务、同载荷，只改客户端
连接上限）：

| 客户端连接上限 | mixed rps | p50 | p95 |
| ---: | ---: | ---: | ---: |
| 12（旧 harness：按 `concurrency` 而非 worker 总数 sizing） | 238.9 | 185.4ms | 879ms |
| 76（修复后：按 72 worker sizing） | 156.5 | 302.4ms | 1250ms |

即：**提高 offer 并发反而使吞吐从 239 降到 157 rps**，属超出饱和点后的争用塌陷，
不是排队等待。此前记录在案的 `mixed` 281 rps / p50 234ms 是**客户端连接饥饿**造成的
假值（72 worker 只有 12 条连接），已作废；该场景「p50 高于任一单场景 p99」不再是
待查缺陷，而是**跨场景混合负载本身的属性**。

⚠️ **连接池已修复**（见 `backend/database.py::_pool_kwargs`）：SQLAlchemy 默认 QueuePool
上限 15，`pool.checkout()` 同步跑在事件循环上，而 `c=32` 时**连接需求峰值实测 23 条**
（SQLAlchemy 池 `checkout`/`checkin` 事件埋点；`c=8` 峰值仅 7）→ 需求顶穿上限后循环被钉死。
关键点：同步 `checkout()` 使「缺连接」不是**排队**而是**停摆** —— 循环一卡，在飞的请求就无法
完成、无法归还连接，形成正反馈。（修前 `chat` `c=32` 为 4.8 rps + 32 × 30s 客户端超时，
连接持有 p95 = 30,046ms；修后 246 rps、0 错、持有 p95 51ms。）
修复方式为 `pool_size=20` / `max_overflow=40` / `pool_timeout` 30s→5s。
**内存型 SQLite 必须跳过该 sizing**（`SingletonThreadPool` 会拒绝这些参数）。

**容量规划**：池上限必须 **> 峰值并发连接需求**（本例 23）。实测连接持有 8.3ms@c=8 /
24.3ms@c=32 —— **不等于 handler 的 ~2ms CPU 时间**（差额是 DB 往返 + 预检 ping + 提交），
所以「handler 很快 ⇒ 连接池够用」是错误推理。移植到 PostgreSQL / 多 worker 时必须重测峰值，
**不要照抄 20+40**。

生产环境用 `backend/perf/load_test.py` 重测并记录到运维文档（注意其 docstring 中的
stdout 消费与限流/上游三条要求，否则测得的数字无效）。


## 7. 发布后迭代

- 跟踪 `requirements*.txt` 安全更新（建议每月一次依赖审计）
- 拦截规则误报/漏报反馈渠道已建立
- 版本发布走 CI 全绿后发布
