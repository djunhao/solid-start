// app.config.ts
import { defineConfig } from "@solidjs/start/config";
import { TanStackRouterVite } from "@tanstack/router-plugin/vite";
import tailwindcss from "@tailwindcss/vite";
var app_config_default = defineConfig({
  vite: {
    plugins: [
      TanStackRouterVite({ target: "solid" }),
      tailwindcss()
    ]
  }
});
export {
  app_config_default as default
};
