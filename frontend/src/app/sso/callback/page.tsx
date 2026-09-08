"use client";

/**
 * OIDC SSO callback landing page.
 *
 * The backend completes the authorization-code + PKCE exchange and redirects
 * the browser here with the session in the URL fragment:
 *   /sso/callback#access_token=..&expires_at=..&token_type=bearer
 * (errors arrive as #error=..&error_description=..).
 *
 * The fragment never reaches any server log; we hand the token to the console
 * SPA through sessionStorage and immediately navigate to the main page, where
 * the boot sequence restores the session and validates it against /auth/me.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, ArrowLeft, LogIn, Shield } from "lucide-react";

// Keep in sync with the handoff reader in src/app/page.tsx.
const SSO_HANDOFF_KEY = "shadow-agent-sso-handoff";

const ERROR_MESSAGES: Record<string, string> = {
  sso_invalid_state: "登录状态已过期或无效，请重新发起 SSO 登录。",
  sso_not_configured: "该组织已停用或删除了 SSO 配置。",
  sso_token_exchange_failed: "身份提供方拒绝了授权码，请重新尝试登录。",
  sso_invalid_id_token: "身份提供方返回的 ID Token 校验失败。",
  sso_invalid_nonce: "检测到重放攻击风险，已终止本次登录。",
  sso_missing_id_token: "身份提供方未返回 ID Token。",
  sso_missing_code: "身份提供方未返回授权码。",
  sso_user_inactive: "该控制台账号已被停用。",
  sso_jit_disabled: "该组织未开放 SSO 自动开户，请先联系管理员创建账号。",
  access_denied: "已在身份提供方取消授权。",
};

export default function SsoCallbackPage() {
  const [error, setError] = useState<{ code: string; description: string } | null>(null);
  const [redirecting, setRedirecting] = useState(false);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      const fragment = new URLSearchParams(window.location.hash.replace(/^#/, ""));
      const accessToken = fragment.get("access_token");
      const errorCode = fragment.get("error");

      if (accessToken) {
        const handoff = {
          access_token: accessToken,
          token_type: fragment.get("token_type") || "bearer",
          expires_at: Number(fragment.get("expires_at") || 0),
        };
        try {
          window.sessionStorage.setItem(SSO_HANDOFF_KEY, JSON.stringify(handoff));
        } catch {
          // sessionStorage unavailable — fall through to the error UI.
          setError({
            code: "sso_handoff_failed",
            description: "浏览器存储不可用，无法完成 SSO 登录接力。",
          });
          return;
        }
        // Wipe the token from the address bar before entering the console.
        window.history.replaceState(null, "", "/sso/callback");
        setRedirecting(true);
        window.setTimeout(() => window.location.replace("/"), 120);
        return;
      }

      setError({
        code: errorCode || "sso_failed",
        description:
          fragment.get("error_description") ||
          "单点登录未返回会话令牌，请重新发起登录。",
      });
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_18%_0%,var(--page-glow-a),transparent_32rem),radial-gradient(circle_at_86%_16%,var(--page-glow-b),transparent_32rem)]" />
      <section className="relative w-full max-w-md rounded-md border border-[var(--panel-border)] bg-[var(--panel-bg)] p-6 shadow-[var(--panel-shadow)] backdrop-blur-[26px]">
        <div className="flex items-center gap-3">
          <span className="flex h-10 w-10 items-center justify-center rounded-md border border-teal-300/30 bg-teal-400/10">
            <Shield className="h-5 w-5 text-teal-200" aria-hidden />
          </span>
          <div>
            <h1 className="text-lg font-semibold text-white">SSO 登录</h1>
            <p className="text-xs text-zinc-400">Shadow Agent 单点登录回调</p>
          </div>
        </div>

        {redirecting ? (
          <div className="mt-6 flex items-center gap-3 text-sm text-zinc-300">
            <LogIn className="h-4 w-4 animate-pulse text-teal-200" aria-hidden />
            正在进入控制台……
          </div>
        ) : (
          <div className="mt-6 space-y-4">
            <div className="flex items-start gap-3 rounded-md border border-amber-300/25 bg-amber-400/10 p-3 text-sm leading-6 text-amber-100">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden />
              <span>
                {ERROR_MESSAGES[error?.code ?? ""] || "单点登录失败，请重新发起登录。"}
                {error?.description ? (
                  <span className="mt-1 block text-xs text-amber-200/70">{error.description}</span>
                ) : null}
              </span>
            </div>
            <button
              type="button"
              onClick={() => window.location.replace("/")}
              className="inline-flex min-h-10 w-full items-center justify-center gap-2 rounded-md border border-teal-200/40 bg-teal-300 px-3 text-sm font-medium text-zinc-950 transition hover:border-teal-100/70 hover:bg-teal-200"
            >
              <ArrowLeft className="h-4 w-4" aria-hidden />
              返回登录页
            </button>
          </div>
        )}
      </section>
    </main>
  );
}
