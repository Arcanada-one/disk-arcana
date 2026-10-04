import ts from "typescript";
import path from "node:path";
import { readFileSync } from "node:fs";

/**
 * Retain source type contracts in the bundled JavaScript. esbuild preserves
 * comments tagged @preserve; the ordinary strict JS compiler checks them.
 * This handles the TypeScript syntax used by this plugin, not arbitrary TS.
 * @param {string} source
 * @param {string} filename
 * @param {string} outputDirectory
 */
export function retainTypes(source, filename, outputDirectory) {
  const file = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true);
  /** @type {Map<string, string>} */
  const names = new Map();
  /** @param {string} moduleName */
  const moduleRef = (moduleName) => moduleName.startsWith(".")
    ? "./" + path.relative(outputDirectory, path.resolve(path.dirname(filename), moduleName)).split(path.sep).join("/")
    : moduleName;
  /** @param {string} moduleName @param {string} exported */
  function localClass(moduleName, exported) {
    if (!moduleName.startsWith(".")) return undefined;
    const target = path.resolve(path.dirname(filename), moduleName + ".ts");
    const parsed = ts.createSourceFile(target, readFileSync(target, "utf8"), ts.ScriptTarget.Latest, true);
    return parsed.statements.find(statement => ts.isClassDeclaration(statement) &&
      statement.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword) &&
      (exported === "default" ? statement.modifiers.some(m => m.kind === ts.SyntaxKind.DefaultKeyword) : statement.name?.text === exported));
  }
  /** @param {string} moduleName @param {string} exported */
  function reference(moduleName, exported) {
    const declaration = localClass(moduleName, exported);
    // Bundled classes must reference each other, not nominal private members
    // of a distinct class declaration in an imported TypeScript source file.
    return declaration && ts.isClassDeclaration(declaration) && declaration.name
      ? declaration.name.text : `import(${JSON.stringify(moduleRef(moduleName))}).${exported}`;
  }
  const ownModule = "./" + path.relative(outputDirectory, filename).replace(/\.ts$/, "").split(path.sep).join("/");
  for (const statement of file.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      const moduleName = statement.moduleSpecifier.text;
      const clause = statement.importClause;
      if (clause?.name) names.set(clause.name.text, reference(moduleName, "default"));
      if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const item of clause.namedBindings.elements) {
          names.set(item.name.text, reference(moduleName, item.propertyName?.text ?? item.name.text));
        }
      }
    }
    if ((ts.isInterfaceDeclaration(statement) || ts.isTypeAliasDeclaration(statement) || ts.isClassDeclaration(statement)) && statement.name) {
      const exported = statement.modifiers?.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
      if (exported) {
        const isDefault = statement.modifiers?.some(m => m.kind === ts.SyntaxKind.DefaultKeyword);
        names.set(statement.name.text, ts.isClassDeclaration(statement) ? statement.name.text : `import(${JSON.stringify(ownModule)}).${isDefault ? "default" : statement.name.text}`);
      }
    }
  }
  /** @param {ts.TypeNode} node */
  function typeText(node) {
    const result = ts.transform(node, [context => root => {
      /** @type {ts.Visitor} */
      const visit = child => {
        // Rewrite identifiers only in type positions, never property names or
        // string literals (for example a union's protocol values).
        if (ts.isTypeReferenceNode(child) && ts.isIdentifier(child.typeName) && names.has(child.typeName.text)) {
          const args = child.typeArguments?.map(typeText);
          return ts.factory.createTypeReferenceNode(names.get(child.typeName.text) + (args?.length ? `<${args.join(", ")}>` : ""));
        }
        if (ts.isTypeQueryNode(child) && ts.isIdentifier(child.exprName) && names.has(child.exprName.text)) {
          return ts.factory.createTypeReferenceNode(`typeof ${names.get(child.exprName.text)}`);
        }
        return ts.visitEachChild(child, visit, context);
      };
      const transformed = ts.visitNode(root, visit);
      if (!transformed || !ts.isTypeNode(transformed)) throw new Error("Expected transformed type node");
      return transformed;
    }]);
    const text = ts.createPrinter().printNode(ts.EmitHint.Unspecified, result.transformed[0], file);
    result.dispose();
    return text;
  }
  /** @type {{pos: number, text: string}[]} */
  const inserts = [];
  /** @param {ts.Node} node */
  function visit(node) {
    /** @type {string[]} */
    const tags = [];
    if (ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node)) {
      for (const generic of node.typeParameters ?? []) {
        const constraint = generic.constraint ? `{${typeText(generic.constraint)}} ` : "";
        const name = generic.default ? `[${generic.name.text}=${typeText(generic.default)}]` : generic.name.text;
        tags.push(`@template ${constraint}${name}`);
      }
      for (const parameter of node.parameters) {
        if (!ts.isIdentifier(parameter.name) || !parameter.type || parameter.dotDotDotToken) throw new Error(`Untyped/destructured parameter in ${filename}`);
        const name = parameter.questionToken || parameter.initializer ? `[${parameter.name.text}]` : parameter.name.text;
        tags.push(`@param {${typeText(parameter.type)}} ${name}`);
      }
      if (node.type) tags.push(`@returns {${typeText(node.type)}}`);
    } else if (ts.isPropertyDeclaration(node) && node.type) {
      tags.push(`@type {${typeText(node.type)}}`);
    } else if (ts.isVariableStatement(node) && node.declarationList.declarations.length === 1) {
      const declaration = node.declarationList.declarations[0];
      if (declaration.type) tags.push(`@type {${typeText(declaration.type)}}`);
    } else if (ts.isAsExpression(node) || ts.isTypeAssertionExpression(node)) {
      // esbuild removes cast parentheses, which changes JSDoc cast binding.
      // Refuse that unsupported transformation rather than claim preserved types.
      throw new Error(`Type assertions require a runtime guard or contextual type in ${filename}`);
    }
    if (tags.length) inserts.push({pos: node.getStart(file), text: `/** @preserve\n * ${tags.join("\n * ")}\n */\n`});
    ts.forEachChild(node, visit);
  }
  visit(file);
  // Stable reverse insertion keeps adjacent comments in
  // their original AST order. No diagnostics are suppressed or types widened.
  let result = source;
  for (const insert of inserts.sort((a, b) => b.pos - a.pos)) result = result.slice(0, insert.pos) + insert.text + result.slice(insert.pos);
  return result;
}
