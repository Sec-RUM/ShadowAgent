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
- [ ] 登录连续失败触发账户锁定（429）
- [ ] 停用账户后其 JWT 立即失效
- [ ] 审批单二次审批返回 409（状态机完整）
- [ ] 无任何测试后门/调试端点残留（`/docs`、`/redoc` 视需要经反代屏蔽）

## 4. 可观测性与运维

- [ ] Prometheus 已抓取 `/metrics`（管理员凭证），告警规则覆盖 5xx 比率、延迟 P99、限流触发量
- [ ] 日志外送集中系统（审计防篡改）
- [ ] 日志保留期已按 [gdpr.md](compliance/gdpr.md) 第 5 节决策并设置 `SHADOW_AGENT_*_RETENTION_DAYS` 环境变量（内置自动清理，默认拦截/告警/重放 180 天、审计 365 天）
- [ ] `/metrics` 中 `shadow_agent_retention_purged_rows_total` 已纳入监控（首次大额清理属预期行为）
- [ ] 备份恢复演练至少完成一次
- [ ] Redis 故障时的 fail-open 降级行为已纳入应急预案（限流退化为单实例）

## 5. 合规

- [ ] 面向欧盟：GDPR 数据映射与告知文本完成（见 [gdpr.md](compliance/gdpr.md)）
- [ ] 面向中国境内：等保定级备案与自查表完成（见 [mlps-2.0.md](compliance/mlps-2.0.md)）
- [ ] 与上游 LLM 提供商签署数据处理协议
- [ ] 工具拦截策略（黑名单/工具权限）已按业务场景评审

## 6. 性能验收（参考基线：开发机并发 8 × 10s）

| 场景 | 基线 | 验收目标 |
| --- | --- | --- |
| GET /health | 463 rps, p95 19ms | 按容量规划设定 |
| POST /chat/completions（放行） | 263 rps, p95 33ms | p95 < 100ms（不含上游延迟） |
| POST /chat/completions（阻断） | 107 rps, p95 118ms | 阻断路径不劣化放行路径 3 倍以上 |
| POST /analyze | 288 rps, p95 35ms | — |

生产环境用 `backend/perf/load_test.py` 重测并记录到运维文档。

## 7. 发布后迭代

- 跟踪 `requirements*.txt` 安全更新（建议每月一次依赖审计）
- 拦截规则误报/漏报反馈渠道已建立
- 版本发布走 CI 全绿后发布
