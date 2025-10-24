import { router } from "./router";
import { RouterProvider } from "@tanstack/solid-router";

import "./app.css";

export default function App() {
  // Provide an explicit (empty) context object to RouterProvider to avoid injecting `undefined` values.
  // The AuthProvider is mounted under the root route, so route-level context is not required here.
  return <RouterProvider router={router} />;
}
