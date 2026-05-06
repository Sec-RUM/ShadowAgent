# 影子智能体 (Shadow Agent)

![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=nextdotjs)
![FastAPI](https://img.shields.io/badge/FastAPI-0.136-009688?logo=fastapi)
![SQLite](https://img.shields.io/badge/SQLite-Log%20Persistence-003B57?logo=sqlite)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-TBD-lightgrey)

影子智能体是面向大语言模型 Agent 运行时的中间层安全沙箱。项目重点防御外部插件、检索内容、第三方 API 返回值引入的间接提示词注入 (Indirect Prompt Injection)，以及模型在工具调用链路中的越权访问风险。

系统设计目标是在不破坏现有 Agent 框架接入方式的前提下，为 Prompt、外部上下文和工具调用增加一层低延迟、可审计、可持续演进的安全控制面。

## 核心架构

**代理层 (Proxy Layer)**  
以 FastAPI 实现 OpenAI 风格的 `/api/v1/chat/completions` 网关入口，负责接收上游 Agent 请求、抽取用户指令、承载外部上下文并向后续模型调用链路透明转发。

**引擎层 (Purification Engine)**  
通过指令/数据解耦，将用户可信指令与外部不可信数据分离处理。当前版本包含规则化的提示词注入识别与工具权限检查骨架，后续会接入轻量本地模型、语义相似度审计、敏感词和黑白名单策略。

**沙箱层 (Sandbox Layer)**  
围绕工具名、参数和策略上下文做多级权限校验，将高风险外部 API 调用结果和敏感操作封装在受控边界内，并将拦截事件沉淀为可查询日志。

**管理端 (Dashboard)**  
基于 Next.js App Router、TypeScript 和 Tailwind CSS 构建安全运营大屏，用于展示拦截日志、运行态指标和策略状态。

## 快速开始

### 克隆项目

```powershell
git clone https://github.com/ZacharyRiser/ShadowAgent.git
cd ShadowAgent
```

### 启动后端

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

后端健康检查：

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

运行网关烟测：

```powershell
python test_gateway.py
```

### 启动前端

```powershell
cd ..\frontend
npm install
$env:SHADOW_AGENT_API_BASE="http://127.0.0.1:8000"
npm run dev
```

打开浏览器访问：

```text
http://localhost:3000
```

## API 概览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 网关健康检查 |
| `POST` | `/api/v1/chat/completions` | OpenAI 风格聊天网关入口，串联安全审计流程 |
| `GET` | `/api/v1/logs` | 查询最新拦截日志，供管理端大屏消费 |

## 项目目录

```text
ShadowAgent
├─ README.md
├─ backend
│  ├─ README.md
│  ├─ database.py
│  ├─ main.py
│  ├─ models.py
│  ├─ requirements.txt
│  ├─ security_engine.py
│  └─ test_gateway.py
└─ frontend
   ├─ README.md
   ├─ eslint.config.mjs
   ├─ next.config.ts
   ├─ package-lock.json
   ├─ package.json
   ├─ postcss.config.mjs
   ├─ public
   │  ├─ file.svg
   │  ├─ globe.svg
   │  ├─ next.svg
   │  ├─ vercel.svg
   │  └─ window.svg
   ├─ src
   │  └─ app
   │     ├─ favicon.ico
   │     ├─ globals.css
   │     ├─ layout.tsx
   │     └─ page.tsx
   └─ tsconfig.json
```

## 当前能力

- OpenAI 兼容风格的 FastAPI 网关入口。
- 指令/数据解耦、提示词注入检测、工具权限检查骨架。
- SQLite + SQLAlchemy 拦截日志持久化。
- 面向安全运营的 Next.js 管理大屏骨架。

## 路线规划

- 接入轻量级本地语义审计模型或 DeepSeek 审计链路。
- 增加敏感词、正则、黑白名单和插件权限策略配置。
- 引入 PostgreSQL、Redis、速率限制和高速缓存。
- 完善管理端日志检索、策略编辑、插件授权和态势感知视图。
