import { readFileSync } from "node:fs";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `vite preview` serves the build with the same headers as Vercel (vercel.json), so the
// content security policy is exercised locally too.
const vercel = JSON.parse(readFileSync(new URL("./vercel.json", import.meta.url), "utf8"));
const headers: Record<string, string> = {};
for (const header of vercel.headers[0].headers) headers[header.key] = header.value;

export default defineConfig({
  plugins: [react()],
  server: { host: "127.0.0.1" },
  preview: { host: "127.0.0.1", headers },
});
