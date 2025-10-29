import {
  Link,
  Outlet,
  createRootRoute,
  createRootRouteWithContext,
} from "@tanstack/solid-router";

import { clientOnly } from "@solidjs/start";
import { Suspense } from "solid-js";
import type { Auth } from "../utils/auth";
import { AuthProvider } from "~/context/auth";

const Devtools = clientOnly(() => import("../components/Devtools"));

export const Route = createRootRoute({
  component: RootComponent,
  notFoundComponent: () => {
    return <p>This setting page doesn't exist!</p>;
  },
});

function RootComponent() {
  return (
    <div class="bg-gray-50 min-h-screen">
      <nav class="flex items-center h-16 backdrop-blur-sm shadow-lg gap-8 p-6">
        <Link
          class="px-6 py-2 rounded-2xl text-blue-500 hover:text-blue-700 hover:outline hover:outline-cyan-400 hover:outline-offset-2"
          to="/"
        >
          Index
        </Link>
        <Link
          class="px-6 py-2 rounded-2xl text-blue-500 hover:text-blue-700 hover:outline hover:outline-cyan-400 hover:outline-offset-2"
          to="/about"
        >
          About
        </Link>
        <Link
          class="px-6 py-2 rounded-2xl text-blue-500 hover:text-blue-700 hover:outline hover:outline-cyan-400 hover:outline-offset-2"
          to="/profile"
        >
          Profile
        </Link>
        <Link
          class="px-6 py-2 rounded-2xl text-blue-500 hover:text-blue-700 hover:outline hover:outline-cyan-400 hover:outline-offset-2"
          to="/auth/login"
        >
          Login
        </Link>
      </nav>
      <main class="min-h-[calc(100vh-4rem)]">
        <Suspense>
          <AuthProvider>
            <Outlet />
          </AuthProvider>
          <Devtools />
        </Suspense>
      </main>
    </div>
  );
}
