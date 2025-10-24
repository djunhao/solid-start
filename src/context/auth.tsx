// src/context/auth.tsx
import { createContext, useContext, createSignal, onMount, JSX } from "solid-js";

type User = { id: string; name: string } | null;

type AuthContextType = {
  user: User;
  loading: boolean;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
};

/**
 * AuthProvider
 *
 * Responsibilities:
 * - Maintain client-side auth state (`user`, `loading`)
 * - Expose `login` and `logout` helpers that call your backend APIs
 * - Initialize state on mount by calling `/api/auth/me` (expects cookie-based auth)
 *
 * Notes / Best practices:
 * - Prefer HttpOnly cookies (set by the server) for session/JWT to avoid XSS token theft.
 * - Always use `credentials: 'include'` for fetch calls that rely on cookies.
 * - For SSR: perform auth checks on the server (read cookies from request) and return initial user data
 *   to avoid client-side flashes. Route-level guards (beforeLoad) should also use server-side checks.
 */

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider(props: { children: JSX.Element }) {
  const [user, setUser] = createSignal<User>(null);
  const [loading, setLoading] = createSignal<boolean>(true);

  // Initialize auth state: call backend to see if there's an active session.
  // This assumes the backend sets an HttpOnly cookie on login and that /api/auth/me uses that cookie.
  onMount(async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/auth/me", {
        method: "GET",
        credentials: "include",
        headers: {
          "Accept": "application/json",
        },
      });
      if (res.ok) {
        const data = await res.json();
        // Expecting { user: { id, name } } or similar
        setUser((data && data.user) || null);
      } else {
        setUser(null);
      }
    } catch (e) {
      // network / unexpected error
      setUser(null);
    } finally {
      setLoading(false);
    }
  });

  // Login: POST credentials to server. Server should set HttpOnly cookie and return user.
  async function login(username: string, password: string) {
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        credentials: "include", // important when server sets cookies
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        return false;
      }

      const data = await res.json();
      // Server is expected to set the auth cookie; it may also return user payload
      setUser((data && data.user) || null);
      return true;
    } catch (e) {
      return false;
    }
  }

  // Logout: call backend to clear session and clear client state
  async function logout() {
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "include",
        headers: {
          "Accept": "application/json",
        },
      });
    } catch (e) {
      // ignore errors but ensure state cleared
    } finally {
      setUser(null);
    }
  }

  const ctx: AuthContextType = {
    get user() {
      return user();
    },
    get loading() {
      return loading();
    },
    login,
    logout,
  };

  return <AuthContext.Provider value={ctx}>{props.children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
