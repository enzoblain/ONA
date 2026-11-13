// Bundles the wallet page into dist/ (index.html, wallet.js, wallet.css), which the desktop apps embed and serve.
// Run: npm ci && npm run build (versions pinned in package.json and package-lock.json).
import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";

mkdirSync("dist", { recursive: true });
await build({
  entryPoints: ["src/main.js"],
  bundle: true,
  minify: true,
  format: "iife",
  platform: "browser",
  target: ["es2020"],
  outfile: "dist/wallet.js",
  legalComments: "eof",
  define: { "process.env.NODE_ENV": '"production"', global: "globalThis" },
  // Some wallet libraries read Node's `process` (process.browser, process.nextTick): a minimal one for the browser.
  banner: {
    js: "var process=globalThis.process||{env:{NODE_ENV:'production'},browser:true,version:'',versions:{},nextTick:function(f){var a=[].slice.call(arguments,1);queueMicrotask(function(){f.apply(null,a)})}};",
  },
  // Node built-ins some wallet libraries import, replaced by what they use of them (src/shims).
  alias: { crypto: "./src/shims/crypto.js", util: "./src/shims/util.js" },
  logLevel: "warning",
});
copyFileSync("src/index.html", "dist/index.html");
copyFileSync("node_modules/@near-wallet-selector/modal-ui/styles.css", "dist/wallet.css");
