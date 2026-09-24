import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// Aletheia WebUI 构建配置。
//
// 依据 docs/06 §8：
//   · 前端框架 React + TypeScript；构建 Vite；不做 SSR（本地工具无 SEO 需求）
//   · API 契约从 05 的 Protobuf 生成 TypeScript 类型（Q14 门禁）
//   · 打包后静态资源由 Go `embed` 进 alethd 二进制（单二进制分发）
//
// outDir 固定为 dist/，与 cmd/alethd 的 go:embed 路径约定一致
// （Makefile 在 make build 时把 dist/ 复制到 cmd/alethd/webdist）。
export default defineConfig({
  plugins: [react()],

  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      "@gen": fileURLToPath(new URL("./src/gen", import.meta.url)),
    },
  },

  build: {
    outDir: "dist",
    // 产物直接嵌入 Go 二进制，不需要 sourcemap 一并进包。
    sourcemap: false,
    // alethd 以相对路径 /assets/... 提供静态资源，base 用默认 "/"。
    emptyOutDir: true,
    target: "es2022",
  },

  server: {
    // 开发时代理由 vite 起在 7724，避开 alethd 的 7723。
    port: 7724,
    // 开发时代理到本地 alethd（对齐 02 §7.5：WebUI 与 daemon 的 API 直连）。
    proxy: {
      "/grpc": {
        target: `http://${process.env.ALETH_DEV_API ?? "127.0.0.1:7723"}`,
        changeOrigin: true,
      },
    },
  },
});
