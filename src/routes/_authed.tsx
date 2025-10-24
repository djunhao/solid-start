// src/routes/_authed.tsx
import { createFileRoute, redirect, Outlet } from "@tanstack/solid-router";

/**
 * _authed route: acts as a layout + route guard for protected child routes.
 *
 * Behavior:
 * - Client-side: beforeLoad will call GET /api/auth/me with credentials: 'include'
 *   to validate the current session (expects server to set HttpOnly cookie or similar).
 *   If the API returns 200 and user info, the user is allowed and `{ user }` is returned
 *   for child routes. Otherwise we redirect to /login.
 *
 * - Server-side (SSR): beforeLoad also runs on the server. You MUST validate auth
 *   using the incoming request (cookies / headers) on the server and either:
 *     - return { user } (allow rendering)
 *     - or throw redirect({ to: '/login' }) to block access
 *
 *   Many server integrations pass request/context into beforeLoad. Implement server-side
 *   validation there (this client-side file contains comments and a client-side fetch;
 *   adapt server-side logic in your server entry or route integration as needed).
 */

export const Route = createFileRoute("/_authed")({
  beforeLoad: async ({ location }) => {
    // Client-side: call backend to verify session
    if (typeof window !== "undefined") {
      try {
        const res = await fetch("/api/auth/me", {
          method: "GET",
          credentials: "include",
          headers: { Accept: "application/json" },
        });

        if (!res.ok) {
          // Not authenticated -> redirect to login
          throw redirect({ to: "/auth/login" });
        }

        const data = await res.json();
        // Expect backend to return { user: { id, name, ... } }
        return { user: data.user ?? null };
      } catch (e) {
        // On network/error or non-OK response, redirect to login
        throw redirect({ to: "/auth/login" });
      }
    }

    // Server-side: implement validation using request cookies/headers.
    // Example approaches (implement in your server integration / adapter):
    //  - Read cookie from incoming request headers, verify session/JWT, and return { user }.
    //  - If invalid, throw redirect({ to: '/login' }).
    //
    // Note: We don't perform server-side checks here because access to the
    // request object depends on the server adapter. Add server-side logic
    // in your SSR entry, middleware, or extend this beforeLoad to use the
    // provided context/request object if available.
    return;
  },
  component: LayoutComponent,
});

function LayoutComponent() {
  // Render layout for all protected children. Child routes will receive loader
  // data returned from beforeLoad (e.g. `user`).
  return <Outlet />;
}
