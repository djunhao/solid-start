// new-solid-start/src/routes/_authed.profile.tsx
import { createFileRoute, useNavigate } from "@tanstack/solid-router";
import { createEffect, JSX } from "solid-js";
import { useAuth } from "~/context/auth";

export const Route = createFileRoute("/_authed/profile")({
  component: RouteComponent,
});

function RouteComponent(): JSX.Element {
  const auth = useAuth();
  const navigate = useNavigate();

  // If not authenticated on the client, redirect to login
  createEffect(() => {
    if (!auth.loading && !auth.user) {
      try {
        navigate({ to: "/auth/login", replace: true });
      } catch {
        if (typeof window !== "undefined") {
          window.location.href = "/login";
        }
      }
    }
  });

  const handleLogout = async () => {
    await auth.logout();
    // navigate to login after logout
    try {
      navigate({ to: "/auth/login", replace: true });
    } catch {
      if (typeof window !== "undefined") {
        window.location.href = "/auth/login";
      }
    }
  };

  if (auth.loading) {
    return <div class="p-6">正在加载用户信息...</div>;
  }

  if (!auth.user) {
    return <div class="p-6">未通过鉴权，正在跳转到登录页...</div>;
  }

  return (
    <div class="p-6">
      <h1 class="text-2xl font-bold mb-4">个人资料页</h1>
      <div class="space-y-2">
        <p>
          <strong>用户 ID：</strong>
          {auth.user.id}
        </p>
        <p>
          <strong>用户名：</strong>
          {auth.user.name}
        </p>
        <button
          class="mt-4 px-4 py-2 rounded bg-red-500 text-white hover:bg-red-600"
          onClick={handleLogout}
        >
          登出
        </button>
      </div>
    </div>
  );
}
