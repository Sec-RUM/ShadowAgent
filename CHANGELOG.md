# Changelog

本项目所有值得记录的变更都写在这里。

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

> **发版说明**
>
> `0.3.0` 是本项目**第一个打 tag 的版本**。此前 26 个提交没有 tag，完整历史见 `git log`。
> 版本号已统一为**单一来源的四处同步**（`backend/main.py`、`sdk/python/pyproject.toml`、
> `sdk/python/shadowagent/__init__.py`、`frontend/package.json`），
> 并由 `backend/tests/test_version_consistency.py` 在 CI 中守护 —— 任一漂移即测试失败。
>
> **发版步骤**：改四处版本号 → 在本文档顶部新增 `## [x.y.z] - YYYY-MM-DD` 段 →
> `cd backend && python -m pytest tests/test_version_consistency.py` →
> 提交 → `git tag -a vX.Y.Z -m "..."` → 推送提交与 tag。

## [Unreleased]

### Added

- **审计留痕脱敏**：`SHADOW_AGENT_LOG_REDACT` = `secrets`（默认）/ `full` / `off`。
  写入 `intercept_logs` / `audit_logs` 的 prompt 与上下文片段统一走
  `app.dlp.redact_for_log()`：默认在原有 `key=value` / `Bearer` 之外，补齐
  AWS / GitHub / OpenAI / Slack / Google 密钥、JWT 与**整段 PEM 私钥**（此前只遮蔽
  `-----BEGIN ...-----` 头部而留下密钥本体）。`full` 追加邮箱 / 中国大陆手机号 / 身份证号；
  `off` 原样存储（仅限把审计库当取证材料的部署，启动时会打警告）。非法取值一律回退 `secrets`。
- **请求体上限**：`SHADOW_AGENT_MAX_BODY_BYTES`（默认 2 MiB，`0` 关闭）。
  两道判定：`Content-Length` 超限则在**读取任何字节前**返回 413；无声明长度（chunked）
  则按实际到达的字节累计，越界即中断。计数区分 `declared` / `actual`，接进
  `shadow_agent_body_rejected_total`。
- **`/docs` 默认关闭**：`SHADOW_AGENT_DOCS_ENABLED`（默认 `false`）控制
  `/docs`、`/redoc`、`/openapi.json` 是否注册 —— 关闭时这些路由**根本不存在**（404），
  而不是"注册了再拦"。
- **CI 依赖漏洞门禁**：新增 `dependency-audit` job，后端
  `pip-audit -r requirements.txt --strict`、前端 `npm audit --audit-level=high`，
  **两侧均为阻断**（前端在 2026-09-27 依赖刷新清零后摘掉 report-only 豁免）；
  `backend/tests/test_ci_gates.py` 守护两者不被静默删除或悄悄改变阻断性。
- 新增 `frontend/tools/osv_npm_audit.py`：当 registry 的审计接口不可达时，
  用 OSV 批量接口直接对 `package-lock.json` 复核，并区分**生产树 / 仅开发**。
- 启动时打印一次**安全姿态**（`log_redact` / `docs` / `max_body_bytes` / `upstream`）。

### Changed

- 中间件顺序显式化并加了注释：限流 → 指标 → CORS → 请求体上限 → 路由。
  把 CORS 移到请求体护栏**外层**，使浏览器客户端能读到 413（限流 429 仍不含 CORS 头，
  属既有缺口，本次未扩大亦未关闭）。
- `security_controls` 拆出 `redact_sensitive_assignments()`（无截断版），
  `redact_text()` 行为与输出**逐字节不变**，仅供组合式脱敏复用。
- **`cryptography` 48.0.0 → 50.0.1**（补丁级升级，非重写）：
  48.0.0 命中 4 条公告（3 HIGH），其中 `GHSA-537c-gmf6-5ccf` 是随 wheel 静态链接的
  OpenSSL 越界读；另外三条 `CVE-2026-69247/69248/69249` 的修复线分别落在 49.0.0 与 50.0.0。
  50.0.1 是该包首个 OSV 报告为空白的补丁版。全量测试在升级后复跑通过。

### Fixed

- **凭据曾以明文落库**：脱敏此前只覆盖 `key=value` 与 `Bearer <token>`，
  一句"我的 key 是 `sk-proj-…`"会原样写进 `intercept_logs.original_prompt`。
  该路径已修复，并有测试固定"旧函数确实漏、新函数确实拦"这一前提。
- 请求体**此前完全无上限**：单个超大 POST 的内存开销只受宿主内存约束。
- **后端运行时依赖存在已知漏洞**：`pip-audit --strict` 从"跑不出来的怀疑"变成"实测通过"，
  入口是 `cryptography` 的那 4 条（详见 Changed）。
- **前端依赖的全部已知公告已清零**（2026-09-27 刷新）：`next` 16.2.4 → **16.3.6**
  （连同 `eslint-config-next`；清掉 24 条公告，含 **2 条未认证 RCE 的 CRITICAL**）、
  `react` / `react-dom` 19.2.4 → 19.3.0、`sharp` → 0.35.4、`postcss` → 8.5.28（≥8.5.23）、
  `nanoid` → 3.3.19（≥3.3.18）、`baseline-browser-mapping` → 2.11.26，
  开发树侧 `js-yaml` 4.3.2 / `browserslist` 4.29.1 / `brace-expansion` 1.1.18+5.0.9 /
  `@babel/core` 7.29.7 一并落位。未引入 `overrides`，未跨任何主版本
  （`typescript` 保持 `^5`、`eslint` 保持 `^9`、`framer-motion` 保持 `^12`）。
  刷新后 OSV 对全量锁文件（437 包）与生产树（58 包）复核均为**零公告**，
  CI 前端审计同步由 report-only 改为阻断。

### Security

- 已核对 `cryptography` 4 条公告在本项目的可达性：本项目只经 PyJWT 用它做
  **RS256/RS384/ES256/ES384 签名校验**（`app/sso.py`，密钥来自已配置的 IdP JWKS），
  不涉及 X.509 路径构建、PKCS#7 EnvelopedData 或证书 name-constraint 校验。
  换言之三条 X.509/PKCS#7 公告在本部署中不可达 —— 但**仍升级**，因为对安全产品而言，
  把已修复的漏洞留在依赖里没有正当理由。

### Performance

- 落库脱敏的开销实测（4 KB 载荷，2000 次取分位）：`redact_for_log` p50 **0.74 ms** / p95 **0.99 ms**，
  相对旧的 `redact_text`（p50 0.196 ms / p95 0.297 ms）增加约 0.54 ms。**放行路径不受影响** ——
  它只在拦截写入、monitor 留痕与后台审计线程（`audit_log_executor`）三条非热路径上调用。
- 请求体护栏的头部解析实测 p50 **0.4 µs**/请求（纯内存操作，无正则）；超限才走计数分支。

## [0.3.0] - 2026-09-26

首个带 tag 的发布。以下按类别汇总自项目初始化以来的主要能力，条目均可追溯至提交历史。

### Added

- **网关核心**：OpenAI 兼容反向代理（`/api/v1/chat/completions`），支持流式（SSE）与非流式；
  对标准 OpenAI 请求与**多轮 function calling 为 drop-in 兼容**。
- **两层注入检测**：正则签名层（强/弱分档，弱签名需指令动词佐证）＋ 本地语义 ML 层（model v4），
  在 `semantic_intent_check()` 融合；层一额外扫描 NFKC 归一化与「ASCII 词内分隔符折叠」视图。
- **三级判定与灰带**：`[0.6144, 0.7644)` 判为疑似并留下 `Monitored` 痕迹 ——
  把阈值邻域的判定从二元改为三级，使重训漂移只改变标签而不改变是否阻断。
- **响应侧 DLP**：内置 AWS / GitHub / OpenAI 等密钥模式，默认 `redact`；
  流式响应的 `content` 与 `tool_calls` 参数均带 hold-back 窗口扫描。
- **工具权限与审批**：工具策略白名单（未知工具默认 `deny`）、审批单二次审批状态机。
- **控制台**：策略 / 工具策略 / 自定义规则 / 托管 API Key / 拦截日志 / 审批 / 告警 / 回放。
- **多租户**：组织、成员管理、每组织 OIDC SSO（含 state 校验与 JIT 角色）。
- **可观测性**：Prometheus `/metrics`、请求延迟直方图、DB 连接池饱和度与超时计数、
  日志队列深度与丢弃计数。
- **留痕与外送**：拦截日志持久化、SSE 实时事件流、告警 webhook（HMAC-SHA256 签名）。
- **Python SDK**：`sdk/python`（`ShadowAgentClient` 与可运行示例）。
- **运维文档**：`docs/launch-checklist.md`（含阻断项标注）、`docs/benchmarks/*`、
  `docs/compliance/{gdpr,mlps-2.0}.md`。
- **CI**：Python 3.11/3.12/3.13 矩阵、Alembic 迁移校验、Redis 共享态真跑、
  前端 lint + build、前后端双镜像构建。

### Changed

- 语义阈值改为**由外部良性标定探针实测得出**（`0.7644` = 探针最高 `0.7344` + 边际 0.03），
  不再是写死的下限 —— 阈值从此不再是魔数。
- 修复覆盖率打分中「字符 n-gram 对普通词生效」的特征病灶；在同一零误报口径下，可买到的
  留出召回由 41.4% 提升到 **78.8%**。
- 数据库连接池按请求路径并发重新定容；池超时由裸 500 改为 **503 + `Retry-After`**。
- 日志默认交给后台 `QueueListener` 线程（`SHADOW_AGENT_LOG_ASYNC=0` 可回退同步写）。
- 支持 `SHADOW_AGENT_DATABASE_URL`（**PostgreSQL 有专门迁移分支**）与可选
  `SHADOW_AGENT_REDIS_URL` 多实例共享态。

### Fixed

- 修掉 `bypass` 同时出现在弱签名表与指令动词表导致的**自我佐证**硬阻断误报，
  并固化「弱签名与指令动词不得重叠」的结构性守卫。
- 中文「请 + 动词」礼貌请求误报（补齐 `polite_request` 语料族；中文召回 91.9% → 94.1%）。
- 开关滑块未按选中态分叉配色，导致 WCAG 1.4.11 非文本对比度不达标。
- 登录 / 注册缺少邮箱格式校验，且提交无可见反馈（慢请求下读作「点了没反应」）。
- 后端不可达时横幅把网络故障谎报为「注册已关闭」，并把 `Failed to fetch` 原样抛给用户。

### Security

- 安全默认全部落在保守一侧：语义 `enforce`、DLP `redact`、未知工具 `deny`、
  开放注册关闭、控制台 bootstrap 关闭。
- 登录连续失败锁定、按主体与路由的限流、多租户数据隔离、停用账号 JWT 立即失效。
- 远程兜底通道**默认关闭**，且强制四道外发闸门（模式 / 主机白名单 / URL+MODEL 必填 /
  载荷最小化），并**一律绕过 `HTTP_PROXY`**。
- 声明「零网络依赖」的范围限定在**语义检测层（进程内推理）**；出网能力均默认关闭、显式 opt-in。

### Performance

- 语义检测在请求路径上同步调用，层内延迟预算 p95 < 33ms。
- 异步日志把日志写入最坏耗时从 245ms 降到 ≤4.5ms（p95）。
- 性能验收采用**相对判据**（阻断路径 p95 不劣化放行路径 3 倍以上），
  **不以绝对 rps 作门槛**（跨会话漂移 13–20%）。

### Known limitations

- **注入召回 78.8%**（fused 精确率 96.3%，以外部 64 条良性探针标定）—— 约 1/5 的注入仍可穿过。
  建议先以 `monitor` 模式观察，不要以 `enforce` 对外宣称"能拦注入"。
- 1 条同族德语变体漏检登记为**已知未修缺陷**（三条候选修法实测均被否决）。
- 上游**无重试 / 退避 / 熔断**，上游抖动即为硬失败。
- 账号自助（邮箱验证 / 找回密码）未实现；注册默认关闭，需邀请码或管理员签发 API Key。
