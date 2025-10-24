// new-solid-start/src/routes/auth/login.tsx
import { createFileRoute, useNavigate } from "@tanstack/solid-router";
import { createSignal, createEffect } from "solid-js";
import { useAuth } from "~/context/auth";

/**
 * Login page (simulated)
 *
 * - Checks credentials against a mocked DB function
 * - Stores a token in localStorage on success
 * - Redirects to a protected page (e.g. /profile)
 *
 * Demo credentials:
 *  username: demo
 *  password: demo123
 */

export const Route = createFileRoute("/auth/login")({
  component: RouteComponent,
});

function RouteComponent() {
  const [username, setUsername] = createSignal("");
  const [password, setPassword] = createSignal("");
  const [loading, setLoading] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const navigate = useNavigate();
  const auth = useAuth();

  const submit = async (e?: Event) => {
    e?.preventDefault();
    setError(null);

    const u = username().trim();
    const p = password();

    if (!u || !p) {
      setError("请输入用户名和密码");
      return;
    }

    setLoading(true);
    try {
      const ok = await auth.login(u, p);
      if (!ok) {
        setError("用户名或密码错误");
        return;
      }

      // 可选：存储非敏感信息以便展示
      if (typeof window !== "undefined") {
        localStorage.setItem("slem.auth.username", username());
      }

      // 导航到受保护页面（示例：/profile）
      try {
        navigate({ to: "/profile" });
      } catch {
        if (typeof window !== "undefined") {
          window.location.href = "/profile";
        }
      }
    } finally {
      setLoading(false);
    }
  };

  createEffect(() => {
    // auth state and navigation are handled via AuthProvider and submit()
  });

  return (
    <div class="max-w-md mx-auto mt-20 p-6 bg-white rounded shadow">
      <h1 class="text-2xl font-bold mb-4">登录</h1>

      <form onSubmit={submit} class="space-y-4">
        <div>
          <label class="block text-sm font-medium mb-1">用户名</label>
          <input
            value={username()}
            onInput={(e) => setUsername((e.target as HTMLInputElement).value)}
            class="w-full px-3 py-2 border rounded"
            placeholder="demo"
            autocomplete="username"
          />
        </div>

        <div>
          <label class="block text-sm font-medium mb-1">密码</label>
          <input
            type="password"
            value={password()}
            onInput={(e) => setPassword((e.target as HTMLInputElement).value)}
            class="w-full px-3 py-2 border rounded"
            placeholder="demo123"
            autocomplete="current-password"
          />
        </div>

        <div>
          <button
            type="submit"
            class="w-full px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-60"
            disabled={loading()}
          >
            {loading() ? "登录中..." : "登录"}
          </button>
        </div>

        {error() && <div class="text-red-600 text-sm">{error()}</div>}

        <div class="text-sm text-gray-600 mt-2">
          <div>
            示例账号： <strong>demo / demo123</strong>
          </div>
          <div>
            （登录后会把 token 存入 localStorage，受保护路由会读取该 token。）
          </div>
        </div>
      </form>
    </div>
  );
}
