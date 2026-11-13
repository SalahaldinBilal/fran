import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
import path from "path";

const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [solid()],
  clearScreen: false,
  server: {
    warmup: {
      clientFiles: ["./src/**/*.{ts,tsx}", "!./src/**/*.d.ts"],
    },
    port: 1430,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
        protocol: "ws",
        host,
        port: 1431,
      }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**", "**/target/**", "**/crates/**", "**/bundles/**", "**/release-files/**"],
    },
  },
  resolve: {
    alias: {
      "@core": path.resolve(import.meta.dirname, "./src"),
    },
  },
});
