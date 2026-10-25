import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";
import { transformSync } from "esbuild";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { retainTypes } from "../typed-jsdoc.mjs";
import { isConflictAction } from "../src/settings-model";

function compileGenerated(body: string): readonly ts.Diagnostic[] {
  const directory = mkdtempSync(path.join(tmpdir(), "disk-jsdoc-regression-"));
  try {
    const source = `export function echo(value: string): string { ${body} }`;
    const typed = retainTypes(source, path.join(directory, "fixture.ts"), directory);
    const generated = transformSync(typed, { loader: "ts", legalComments: "inline" }).code;
    const output = path.join(directory, "fixture.js");
    writeFileSync(output, generated);
    const program = ts.createProgram([output], {
      strict: true, allowJs: true, checkJs: true, noEmit: true,
      skipLibCheck: true, types: [], target: ts.ScriptTarget.ES2022
    });
    return ts.getPreEmitDiagnostics(program);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe("generated type contracts", () => {
  it("checks emitted bodies against source signatures, including a real negative mutant", () => {
    expect(compileGenerated("return value;")).toEqual([]);
    expect(compileGenerated("return 17;").some(error => error.code === 2322)).toBe(true);
  });

  it("refuses unsupported erased assertions instead of claiming their metadata survived", () => {
    expect(() => retainTypes("const n = value as number;", "/fixture.ts", "/")).toThrow("Type assertions require");
    expect(() => retainTypes("function f({a}: {a: number}) {}", "/fixture.ts", "/")).toThrow("Untyped/destructured parameter");
  });

  it("preserves the generated CommonJS default getter and plugin constructor", () => {
    const module = { exports: {} as Record<string, unknown> };
    const code = readFileSync(fileURLToPath(new URL("../main.js", import.meta.url)), "utf8");
    vm.runInNewContext(code, {
      module,
      require(name: string) {
        if (name !== "obsidian") throw new Error(`Unexpected bundle dependency: ${name}`);
        return { Modal: class {}, PluginSettingTab: class {}, Plugin: class {} };
      }
    });
    expect(Object.keys(module.exports)).toEqual(["default"]);
    expect(module.exports.__esModule).toBe(true);
    expect(Object.getOwnPropertyDescriptor(module.exports, "default")?.get).toBeTypeOf("function");
    const Plugin = module.exports.default as new () => { settings: { daemonUrl: string } };
    expect(new Plugin().settings.daemonUrl).toBe("http://127.0.0.1:9444");
  });

  it("narrows conflict actions from actual runtime values without an erased assertion", () => {
    for (const value of ["keep-local", "keep-remote", "fork-local", "fork-remote", "merge"]) expect(isConflictAction(value)).toBe(true);
    for (const value of [undefined, null, "invalid", 42, {}]) expect(isConflictAction(value)).toBe(false);
  });
});
