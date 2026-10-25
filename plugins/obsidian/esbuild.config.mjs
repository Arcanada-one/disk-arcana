import esbuild from "esbuild";
import { builtinModules } from "node:module";
import process from "node:process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { retainTypes } from "./typed-jsdoc.mjs";

const production = process.argv[2] === "production";
const context = await esbuild.context({
  // An explicit CommonJS entry preserves the existing default getter and
  // __esModule contract without introducing untyped bundler interop helpers.
  stdin: {
    contents: `import DiskArcanaPlugin from "./src/main";
      Object.defineProperty(module.exports, "__esModule", { value: true });
      Object.defineProperty(module.exports, "default", { enumerable: true, get: () => DiskArcanaPlugin });`,
    resolveDir: process.cwd(),
    sourcefile: "plugin-entry.ts",
    loader: "ts"
  },
  legalComments: "inline",
  plugins: [{
    name: "retain-source-type-contracts",
    setup(build) {
      build.onLoad({ filter: /\.ts$/ }, async (args) => ({
        contents: retainTypes(await readFile(args.path, "utf8"), args.path, process.cwd()),
        loader: "ts",
        resolveDir: path.dirname(args.path)
      }));
    }
  }],
  bundle: true,
  external: ["obsidian", "electron", ...builtinModules],
  format: "cjs",
  target: "es2022",
  logLevel: "info",
  sourcemap: production ? false : "inline",
  treeShaking: true,
  outfile: "main.js"
});

if (production) {
  await context.rebuild();
  await context.dispose();
} else {
  await context.watch();
}
