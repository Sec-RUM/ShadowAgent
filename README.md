# 影子智能体 Shadow Agent

![CI](https://github.com/Sec-RUM/ShadowAgent/actions/workflows/ci.yml/badge.svg)
![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=nextdotjs)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

**面向 LLM Agent 运行时的开源安全网关** —— 在你的应用与模型之间加一层低延迟、可审计的安全控制面，防御提示词注入、敏感数据外泄与工具调用越权，且**不改业务代码**（OpenAI SDK 换个 `base_url` 即接入）。

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8000/api/v1", api_key="sak_xxx.yyy")
# 所有请求先过 Shadow Agent：注入被拦截(403)，正常请求透传给上游模型
```

## 它防什么

| 威胁 | 防御机制 |
| --- | --- |
| 直接/间接提示词注入 | 指令-数据解耦 + 多引擎检测（黑名单/语义意图/行为风险），支持**多轮会话全量审计**（不只看最后一条消息） |
| 敏感数据外泄 | 凭据/密钥模式识别 + 输出脱敏（redaction） |
| 危险工具调用 | 工具名+参数级策略引擎，高危操作（删除、外发）强制审批流 |
| 越权访问 | RBAC（admin / security_admin / client / gateway）+ 托管 API Key（可吊销/可设期/角色绑定） |
| 暴力破解 | 登录限速 + 账户锁定 + 登录枚举防护，JWT 可即时吊销 |

## 平台能力

- **安全运营控制台**：拦截日志、策略管理、审批工作流、密钥中心、攻击重放
- **实时告警**：SSE 实时事件流 + 全屏 SOC 安全大屏 + Webhook 推送（Slack/飞书/钉钉，HMAC 签名 + 自动重试）
- **可观测性**：Prometheus `/metrics`（请求计数/延迟直方图/清理指标），运行状态仪表盘
- **合规就绪**：GDPR 日志保留期自动清理、管理操作全量审计、[等保 2.0 / GDPR 指引](./docs/compliance/)
- **工程化**：50+ 测试用例、Alembic 迁移、Docker/compose 部署、CI 矩阵（Python 3.11–3.13）、压测基线（约 260 rps，p95 33ms）

## 架构

```mermaid
flowchart LR
    A["Agent / 应用<br/>(OpenAI SDK · LangChain · SDK)"] -->|"Bearer sak_..."| G

    subgraph G["Shadow Agent 网关"]
        direction TB
        AUTH["认证与限速<br/>RBAC · 托管 Key"]
        ENGINE["安全引擎<br/>指令数据解耦 · 注入检测<br/>行为风险 · 工具权限"]
        AUDIT["审计与告警<br/>拦截日志 · SSE 推送<br/>Webhook"]
    end

    G -->|"放行的请求"| U["上游 LLM<br/>(OpenAI 兼容)"]
    G -->|"403 拦截 + 决策详情"| A
    G --> C["控制台 / SOC 大屏<br/>Next.js"]
    G -.->|"指标"| M["Prometheus<br/>/metrics"]
```

## 快速开始

```powershell
git clone https://github.com/Sec-RUM/ShadowAgent.git
cd ShadowAgent
Copy-Item .env.example .env    # 填入随机密钥（文件头有生成命令）
docker compose up -d --build
```

打开 `http://localhost:3000` 进入控制台；5 分钟完整接入教程（含 OpenAI SDK / Python SDK / 裸 HTTP 三种方式与告警配置）见 **[docs/quickstart.md](./docs/quickstart.md)**。

## 文档

| 文档 | 内容 |
| --- | --- |
| [快速开始](./docs/quickstart.md) | 5 分钟接入：Docker 启动 → 拿 Key → 三行代码 |
| [后端手册](./backend/README.md) | 全部 API、环境变量、测试、迁移、部署 |
| [SDK](./sdk/python/) | Python 客户端（同步/异步，拦截决策一等公民处理） |
| [上线清单](./docs/launch-checklist.md) | 生产环境逐项核对（密钥/架构/合规/性能） |
| [合规指引](./docs/compliance/) | GDPR 数据映射与等保 2.0 条款对照 |

## 安全

发现安全漏洞请查看 [SECURITY.md](./SECURITY.md)，通过私有渠道报告，不要公开披露细节。

## 路线规划

- [x] OpenAI SDK 兼容接入（Bearer 认证 + `/models`）
- [x] 实时告警（SSE 大屏 + Webhook 推送）
- [ ] 响应侧 DLP 扫描（模型输出中的敏感数据检测）
- [ ] 自定义检测规则编辑器（正则/关键词/阈值）与规则包热更新
- [ ] 语义级注入检测（embedding 相似度）
- [ ] 多租户（组织/成员/密钥层级）与 SSO
- [ ] 检测能力公开基准报告（注入语料库 + 检出率/误报率）
