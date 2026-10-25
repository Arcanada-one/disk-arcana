/* Bounded compiler observation derived from Security v7; never a supplied-count admission. */
const fs=require('fs'),path=require('path'),cp=require('child_process'),crypto=require('crypto');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const root=path.resolve(input.root);
const bindingErrors=[];
for(const f of input.files){const full=path.resolve(root,f.path);if(!full.startsWith(root+path.sep)||!fs.existsSync(full)||hash(fs.readFileSync(full))!==f.sha256)bindingErrors.push('SOURCE_BYTES_MISMATCH');}
const ts=require(path.join(root,'apps/api/node_modules/typescript'));
const project=input.compiler_project;
if(!project||typeof project.path!=='string'||path.isAbsolute(project.path)||project.path.split('/').includes('..'))throw Error('METADATA_PROJECT_BINDING_INVALID');
const configPath=path.resolve(root,project.path);
if(!configPath.startsWith(root+path.sep)||!input.files.some(f=>f.path===project.path&&f.sha256===project.sha256)||hash(fs.readFileSync(configPath))!==project.sha256)throw Error('METADATA_PROJECT_BINDING_MISMATCH');
const config=ts.readConfigFile(configPath,ts.sys.readFile);
const parsed=ts.parseJsonConfigFileContent(config.config,ts.sys,path.dirname(configPath));
const options={...parsed.options,noEmit:true,incremental:false};
const expectedHead=input.head;
const actualHead=input.head;
const decoratorRel='apps/api/src/auth/agent-scope.decorator.ts';
const guardRel='apps/api/src/auth/guards/agent-task-scope.guard.ts';
function hash(s){return crypto.createHash('sha256').update(s).digest('hex');}
function analyze(overrides={},claimedHead=expectedHead){
 const errors=[...bindingErrors],unknown=[],classified=[],contextReads=[],contextEscapes=[],containerFlows=[],containerClosure=[],containerEscapePositions=[],rawMetadataEscapes=[];
 if(claimedHead!==actualHead)errors.push('HEAD_BINDING_MISMATCH');
 const host=ts.createCompilerHost(options),original=host.getSourceFile.bind(host);
 host.getSourceFile=(name,version,onError,fresh)=>overrides[path.relative(root,path.resolve(name))]!==undefined?ts.createSourceFile(name,overrides[path.relative(root,path.resolve(name))],version,true):original(name,version,onError,fresh);
 const program=ts.createProgram(parsed.fileNames,options,host),checker=program.getTypeChecker();
 const dec=program.getSourceFile(path.join(root,decoratorRel)),guard=program.getSourceFile(path.join(root,guardRel));
 const projectDiagnostics=[...(config.error?[config.error]:[]),...parsed.errors];
 if(projectDiagnostics.length||!dec||!guard)return {
  errors:['METADATA_PROJECT_MEMBERSHIP_NOT_MEASURED'],
  diagnostics:projectDiagnostics.map(d=>({code:d.code,message:ts.flattenDiagnosticMessageText(d.messageText,' '),file:d.file?path.relative(root,d.file.fileName):null})),
  closed:false};
 const sym=n=>{let s=checker.getSymbolAtLocation(n);if(s?.flags&ts.SymbolFlags.Alias)s=checker.getAliasedSymbol(s);return s;};
 const loc=n=>({file:path.relative(root,n.getSourceFile().fileName),line:n.getSourceFile().getLineAndCharacterOfPosition(n.getStart()).line+1});
 const alias=dec.statements.find(n=>ts.isTypeAliasDeclaration(n)&&n.name.text==='AgentScopeKind');
 const ctx=guard.statements.find(n=>ts.isInterfaceDeclaration(n)&&n.name.text==='AgentScopeContext');
 if(!alias||!ctx)return {errors:['MISSING_DECLARATION'],closed:false};
 const kindSymbol=sym(alias.name),ctxSymbol=sym(ctx.name);
 const ctxKind=checker.getDeclaredTypeOfSymbol(ctxSymbol).getProperty('kind');
 const kindDeclarations=ctxKind?.declarations||[];
 const hasContext=(t,seen=new Set())=>{
  if(!t||seen.has(t))return false;seen.add(t);
  if(t.getSymbol()===ctxSymbol)return true;
  const prop=t.getProperty('kind');
  if(prop&&(prop.declarations||[]).some(d=>kindDeclarations.includes(d)))return true;
  if((t.isUnion()||t.isIntersection())&&t.types.some(x=>hasContext(x,seen)))return true;
  return typeof t.getBaseTypes==='function'&&(t.getBaseTypes()||[]).some(x=>hasContext(x,seen));
 };
 const hasContainer=t=>{const prop=t?.getProperty('agentScope');return prop&&hasContext(checker.getTypeOfSymbolAtLocation(prop,prop.valueDeclaration||prop.declarations[0]));};
 const vars=dec.statements.filter(ts.isVariableStatement).flatMap(s=>s.declarationList.declarations);
 const helper=vars.find(d=>d.name.text==='AgentScope'),key=vars.find(d=>d.name.text==='AGENT_SCOPE_KEY');
 const helperSymbol=helper&&sym(helper.name),keySymbol=key&&sym(key.name);
 const values=ts.isUnionTypeNode(alias.type)?alias.type.types.filter(ts.isLiteralTypeNode).map(t=>t.literal.text):[];
 const metadataCall=helper&&ts.isArrowFunction(helper.initializer)&&helper.initializer.body;
 const dependencyDeclaration=call=>checker.getResolvedSignature(call)?.declaration;
 const declarationAt=(decl,rel)=>!!decl&&fs.realpathSync(decl.getSourceFile().fileName)===fs.realpathSync(path.join(root,rel));
 const parameter=helper?.initializer?.parameters?.[0];
 if(!metadataCall||!ts.isCallExpression(metadataCall)||metadataCall.arguments.length!==2||sym(metadataCall.arguments[0])!==keySymbol||!parameter||!ts.isIdentifier(parameter.name)||sym(metadataCall.arguments[1])!==sym(parameter.name)||!declarationAt(dependencyDeclaration(metadataCall),'apps/api/node_modules/@nestjs/common/decorators/core/set-metadata.decorator.d.ts')||sym(metadataCall.expression)?.name!=='SetMetadata')errors.push('METADATA_HELPER_UNSUPPORTED');
 if(!key||!ts.isStringLiteral(key.initializer)||key.initializer.text!=='mun0043:agentScope')errors.push('METADATA_KEY_CHANGED_OR_UNPROVEN');
 /** @type {import('typescript').SwitchStatement | undefined} */
 let switchNode;
 /** @type {import('typescript').Symbol | undefined} */
 let metadataBinding;
 // Only the observed read-only two-binding scalar extractor grammar is supported.
 // Names do not grant closure: every operand resolves to the actual parameter/local symbol.
 function scalarExtractorGrammar(d){
  const statements=d?.body?.statements;
  if(!statements||statements.length!==3||d.parameters.length!==2)return false;
  const binding=s=>ts.isVariableStatement(s)&&s.declarationList.declarations.length===1&&
   (s.declarationList.flags&ts.NodeFlags.Const)?s.declarationList.declarations[0]:null;
  const container=binding(statements[0]),value=binding(statements[1]);
  if(!container||!value||!ts.isIdentifier(container.name)||!ts.isIdentifier(value.name))return false;
  const source=container.initializer;
  if(!source||!ts.isAsExpression(source)||!ts.isPropertyAccessExpression(source.expression)||
   sym(source.expression.expression)!==sym(d.parameters[0].name)||!['body','params'].includes(source.expression.name.text))return false;
  const asserted=source.type;
  if(!ts.isUnionTypeNode(asserted)||asserted.types.length!==2||
   !asserted.types.some(t=>t.kind===ts.SyntaxKind.UndefinedKeyword))return false;
  const record=asserted.types.find(ts.isTypeReferenceNode);
  if(!record||record.typeName.getText()!=='Record'||record.typeArguments?.length!==2||
   record.typeArguments[0].kind!==ts.SyntaxKind.StringKeyword||
   ![ts.SyntaxKind.StringKeyword,ts.SyntaxKind.UnknownKeyword].includes(record.typeArguments[1].kind))return false;
  const read=value.initializer;
  if(!read||!ts.isElementAccessExpression(read)||!read.questionDotToken||
   sym(read.expression)!==sym(container.name)||sym(read.argumentExpression)!==sym(d.parameters[1].name))return false;
  const ret=statements[2];if(!ts.isReturnStatement(ret)||!ret.expression||!ts.isConditionalExpression(ret.expression))return false;
  const out=ret.expression,condition=out.condition;
  if(sym(out.whenTrue)!==sym(value.name)||!ts.isIdentifier(out.whenFalse)||out.whenFalse.text!=='undefined'||
   !ts.isBinaryExpression(condition)||condition.operatorToken.kind!==ts.SyntaxKind.AmpersandAmpersandToken)return false;
  const type=condition.left,length=condition.right;
  return ts.isBinaryExpression(type)&&type.operatorToken.kind===ts.SyntaxKind.EqualsEqualsEqualsToken&&
   ts.isTypeOfExpression(type.left)&&sym(type.left.expression)===sym(value.name)&&
   ts.isStringLiteral(type.right)&&type.right.text==='string'&&ts.isBinaryExpression(length)&&
   length.operatorToken.kind===ts.SyntaxKind.GreaterThanToken&&ts.isPropertyAccessExpression(length.left)&&
   length.left.name.text==='length'&&sym(length.left.expression)===sym(value.name)&&
   ts.isNumericLiteral(length.right)&&length.right.text==='0';
 }
 const files=program.getSourceFiles().filter(s=>s.fileName.startsWith(root+'/apps/api/src/'));
 const coveredConsumers=new Set();
 function enclosingFunction(n){while(n&&!ts.isFunctionDeclaration(n)&&!ts.isMethodDeclaration(n)&&!ts.isArrowFunction(n))n=n.parent;return n;}
 function classifyRecordRead(n,sf){
  const fn=enclosingFunction(n),parameter=fn?.parameters?.find(p=>sym(p.name)===sym(n.expression)),comparison=n.parent;
  const constant=ts.isBinaryExpression(comparison)&&comparison.operatorToken.kind===ts.SyntaxKind.ExclamationEqualsEqualsToken&&comparison.left===n&&ts.isStringLiteral(comparison.right)?comparison.right.text:null;
  const signature=fn&&checker.getSignatureFromDeclaration(fn),returnType=signature&&checker.getReturnTypeOfSignature(signature);
  const types=returnType?.isUnion()?returnType.types:[returnType];
  const outputKinds=[];
  for(const t of types.filter(Boolean)){const prop=t.getProperty('kind');if(prop){const pt=checker.getTypeOfSymbolAtLocation(prop,fn);if(pt.isStringLiteral())outputKinds.push(pt.value);}}
  const row={...loc(n),expression:n.getText(sf),function:fn?.name?.getText(sf)||null,parameter_symbol_declarations:(sym(n.expression)?.declarations||[]).map(loc),parameter_declared_unknown:parameter?.type?.kind===ts.SyntaxKind.UnknownKeyword,comparison_literal:constant,declared_return_kind_literals:outputKinds};
  if(parameter&&row.parameter_declared_unknown&&constant&&!values.includes(constant)&&outputKinds.includes(constant)&&ts.isFunctionDeclaration(fn))classified.push(row);else unknown.push(row);
 }
 for(const sf of files){
  function visit(n){
   if(ts.isIdentifier(n)&&[kindSymbol,helperSymbol,keySymbol].includes(sym(n)))coveredConsumers.add(path.relative(root,sf.fileName));
   if(ts.isVariableDeclaration(n)&&n.initializer&&ts.isCallExpression(n.initializer)&&n.initializer.arguments[0]&&sym(n.initializer.arguments[0])===keySymbol){
    const d=dependencyDeclaration(n.initializer);
    const call=n.initializer,targets=call.arguments[1],fn=enclosingFunction(n),context=fn?.parameters?.[0];
    const targetNames=targets&&ts.isArrayLiteralExpression(targets)?targets.elements.map(x=>ts.isCallExpression(x)&&x.arguments.length===0&&ts.isPropertyAccessExpression(x.expression)&&context&&sym(x.expression.expression)===sym(context.name)?x.expression.name.text:null):[];
    if(declarationAt(d,'apps/api/node_modules/@nestjs/core/services/reflector.service.d.ts')&&d.name?.text==='getAllAndOverride'&&ts.isPropertyAccessExpression(call.expression)&&call.expression.name.text==='getAllAndOverride'&&call.arguments.length===2&&targetNames.length===2&&targetNames[0]==='getHandler'&&targetNames[1]==='getClass'&&loc(fn||n).file===guardRel&&fn?.name?.getText(sf)==='canActivate'&&checker.getTypeAtLocation(call).isUnion())metadataBinding=sym(n.name);else errors.push('METADATA_READER_UNSUPPORTED');
   }
   if(ts.isSwitchStatement(n)&&checker.getTypeAtLocation(n.expression).aliasSymbol===kindSymbol){if(switchNode)errors.push('MULTIPLE_SCOPE_SWITCHES');switchNode=n;}
   if(ts.isIdentifier(n)&&helperSymbol&&sym(n)===helperSymbol){
    const p=n.parent;
    const declaration=ts.isVariableDeclaration(p)&&p.name===n;
    const imported=ts.isImportSpecifier(p)||ts.isImportClause(p);
    const decoratorCall=ts.isCallExpression(p)&&p.expression===n&&ts.isDecorator(p.parent);
    if(!declaration&&!imported&&!decoratorCall)errors.push('METADATA_HELPER_ESCAPE_UNPROVEN');
   }
   if(ts.isIdentifier(n)&&keySymbol&&sym(n)===keySymbol){
    const p=n.parent;
    const declaration=ts.isVariableDeclaration(p)&&p.name===n;
    const imported=ts.isImportSpecifier(p)||ts.isImportClause(p);
    const writer=p===metadataCall&&p.arguments[0]===n;
    const reader=ts.isCallExpression(p)&&p.arguments[0]===n&&ts.isVariableDeclaration(p.parent)&&metadataBinding&&sym(p.parent.name)===metadataBinding;
    if(!declaration&&!imported&&!writer&&!reader)errors.push('METADATA_KEY_ESCAPE_UNPROVEN');
   }
   if(ts.isCallExpression(n)&&sym(n.expression)===helperSymbol){if(n.arguments.length!==1||!ts.isStringLiteral(n.arguments[0])||!values.includes(n.arguments[0].text)||!ts.isDecorator(n.parent))errors.push('UNKNOWN_METADATA_HELPER_CALL');}
   if(ts.isPropertyAccessExpression(n)&&n.name.text==='kind'||ts.isElementAccessExpression(n)&&ts.isStringLiteral(n.argumentExpression)&&n.argumentExpression.text==='kind'){
    const prop=checker.getTypeAtLocation(n.expression).getProperty('kind');
    if(prop&&(prop.declarations||[]).some(d=>kindDeclarations.includes(d))){
     const p=n.parent,literal=ts.isBinaryExpression(p)&&p.left===n&&ts.isStringLiteral(p.right)?p.right.text:null;
     const safe=ts.isBinaryExpression(p)&&p.operatorToken.kind===ts.SyntaxKind.ExclamationEqualsEqualsToken&&values.includes(literal);
     contextReads.push({...loc(n),expression:n.getText(sf),literal,safe_comparison:safe});if(!safe)errors.push('CONTEXT_KIND_OUTPUT_OR_UNKNOWN_USE');
    }else if(!prop)classifyRecordRead(n,sf);
   }
   if(ts.isExpression(n)&&hasContext(checker.getTypeAtLocation(n))){
    const p=n.parent;
    const nonRuntime=ts.isExpressionWithTypeArguments(n)||ts.isIdentifier(n)&&(ts.isTypeReferenceNode(p)||ts.isExpressionWithTypeArguments(p)||ts.isImportSpecifier(p)||ts.isInterfaceDeclaration(p)||ts.isPropertySignature(p)||ts.isVariableDeclaration(p)&&p.name===n||ts.isPropertyAccessExpression(p)&&p.name===n);
    const parentUse=p.parent;
    const effect=ts.isBinaryExpression(parentUse)&&parentUse.left===p&&parentUse.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&parentUse.operatorToken.kind<=ts.SyntaxKind.LastAssignment||ts.isDeleteExpression(parentUse)||ts.isPostfixUnaryExpression(parentUse)||ts.isPrefixUnaryExpression(parentUse)&&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(parentUse.operator);
    const read=ts.isPropertyAccessExpression(p)&&p.expression===n&&!effect&&!!checker.getNonNullableType(checker.getTypeAtLocation(n)).getProperty(p.name.text);
    const aliasBinding=ts.isVariableDeclaration(p)&&p.initializer===n&&ts.isIdentifier(p.name)&&hasContext(checker.getTypeAtLocation(p.name));
    const test=ts.isPrefixUnaryExpression(p)&&p.operator===ts.SyntaxKind.ExclamationToken;
    const fn=enclosingFunction(n);
    const destination=ts.isBinaryExpression(p)&&p.operatorToken.kind===ts.SyntaxKind.EqualsToken&&p.left===n&&ts.isPropertyAccessExpression(n)&&n.name.text==='agentScope'&&loc(fn||n).file===guardRel&&fn?.name?.getText(sf)==='canActivate';
    if(!nonRuntime&&!read&&!aliasBinding&&!test&&!destination){contextEscapes.push({...loc(n),expression:n.getText(sf).slice(0,300),parent_kind:ts.SyntaxKind[p.kind]});errors.push('CONTEXT_ESCAPE_UNPROVEN');}
   }
   // Track the original metadata value even after switch narrowing removes its alias type.
   if(ts.isIdentifier(n)&&metadataBinding&&sym(n)===metadataBinding){
    const p=n.parent;
    const declaration=ts.isVariableDeclaration(p)&&p.name===n;
    const switchUse=ts.isSwitchStatement(p)&&p.expression===n;
    const booleanTest=ts.isPrefixUnaryExpression(p)&&p.operator===ts.SyntaxKind.ExclamationToken;
    const exhaustive=ts.isVariableDeclaration(p)&&p.initializer===n&&p.type?.kind===ts.SyntaxKind.NeverKeyword;
    const shorthand=ts.isShorthandPropertyAssignment(p)&&p.name===n;
    const object=shorthand&&p.parent;
    const assignment=object?.parent;
    const fn=enclosingFunction(n);
    const contextWrite=shorthand&&ts.isObjectLiteralExpression(object)&&ts.isBinaryExpression(assignment)&&assignment.operatorToken.kind===ts.SyntaxKind.EqualsToken&&ts.isPropertyAccessExpression(assignment.left)&&assignment.left.name.text==='agentScope'&&hasContainer(checker.getTypeAtLocation(assignment.left.expression))&&loc(fn||n).file===guardRel&&fn?.name?.getText(sf)==='canActivate';
    if(!declaration&&!switchUse&&!booleanTest&&!exhaustive&&!contextWrite){errors.push('RAW_METADATA_VALUE_ESCAPE_UNPROVEN');rawMetadataEscapes.push({...loc(n),parent_kind:ts.SyntaxKind[p.kind],parent:p.getText(sf).slice(0,300)});}
   }
   if(ts.isIdentifier(n)&&hasContainer(checker.getTypeAtLocation(n))){
    const p=n.parent;
    const nonRuntime=ts.isParameter(p)&&p.name===n||ts.isTypeAliasDeclaration(p)&&p.name===n||ts.isInterfaceDeclaration(p)&&p.name===n||ts.isTypeReferenceNode(p)||ts.isVariableDeclaration(p)&&p.name===n||ts.isPropertySignature(p)||ts.isImportSpecifier(p)||ts.isPropertyAccessExpression(p)&&p.name===n;
    const safeRead=ts.isPropertyAccessExpression(p)&&p.expression===n;
    const safeAlias=ts.isVariableDeclaration(p)&&p.initializer===n&&ts.isIdentifier(p.name);
    const argument=ts.isCallExpression(p)&&p.arguments.includes(n);
    if(!nonRuntime&&!safeRead&&!safeAlias&&!argument){errors.push('REQUEST_CONTAINER_ESCAPE_UNPROVEN');containerEscapePositions.push({...loc(n),expression:n.getText(sf),parent_kind:ts.SyntaxKind[p.kind],parent:p.getText(sf).slice(0,500)});}
    if(argument){
     const d=dependencyDeclaration(p),parameter=d?.parameters?.[p.arguments.indexOf(n)];
     const parameterSymbol=parameter&&sym(parameter.name);const uses=[],bad=[];let calls=0;
     function trace(x){
      if(ts.isCallExpression(x))calls++;
      // The bounded private extractors are read-only, including all local aliases.
      // Assignment, deletion and updates anywhere in their bodies refuse closure.
      if(ts.isBinaryExpression(x)&&x.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&x.operatorToken.kind<=ts.SyntaxKind.LastAssignment||ts.isDeleteExpression(x)||ts.isPostfixUnaryExpression(x)||ts.isPrefixUnaryExpression(x)&&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(x.operator))bad.push(loc(x));
      if(ts.isIdentifier(x)&&sym(x)===parameterSymbol&&x!==parameter.name){
       const parent=x.parent;
       const effect=ts.isBinaryExpression(parent.parent)&&parent.parent.left===parent&&parent.parent.operatorToken.kind>=ts.SyntaxKind.FirstAssignment&&parent.parent.operatorToken.kind<=ts.SyntaxKind.LastAssignment||ts.isDeleteExpression(parent.parent)||ts.isPostfixUnaryExpression(parent.parent)||ts.isPrefixUnaryExpression(parent.parent)&&[ts.SyntaxKind.PlusPlusToken,ts.SyntaxKind.MinusMinusToken].includes(parent.parent.operator);
       const allowed=ts.isPropertyAccessExpression(parent)&&parent.expression===x&&['body','params'].includes(parent.name.text)&&!effect;
       uses.push({...loc(x),parent_kind:ts.SyntaxKind[parent.kind],read:allowed?parent.name.text:null});if(!allowed)bad.push(loc(x));
      }ts.forEachChild(x,trace);
     }
     if(d?.body&&parameter)trace(d.body);
     const returns=d&&checker.getReturnTypeOfSignature(checker.getSignatureFromDeclaration(d));
     const returnParts=returns?.isUnion()?returns.types:[returns];
     const scalar=returnParts?.length&&returnParts.every(t=>t&&(t.flags&(ts.TypeFlags.String|ts.TypeFlags.Undefined)));
     const privateMethod=d&&ts.isMethodDeclaration(d)&&d.modifiers?.some(m=>m.kind===ts.SyntaxKind.PrivateKeyword);
     const closed=privateMethod&&loc(d).file===guardRel&&uses.length===1&&!bad.length&&!calls&&scalar&&scalarExtractorGrammar(d);
     const row={...loc(n),callee:p.expression.getText(sf),callee_declaration:d?loc(d):null,private_method:!!privateMethod,return_type:returns?checker.typeToString(returns):null,parameter_uses:uses,side_effect_call_count:calls,closed:!!closed};
     if(closed)containerClosure.push(row);else{containerFlows.push(row);errors.push('REQUEST_CONTAINER_FLOW_UNPROVEN');}
    }
   }
   ts.forEachChild(n,visit);
  }
  visit(sf);
 }
 if(!metadataBinding||!switchNode||sym(switchNode.expression)!==metadataBinding)errors.push('SWITCH_NOT_BOUND_TO_METADATA_READER');
 const cases=switchNode?.caseBlock.clauses.filter(n=>'expression' in n).map(n=>ts.isStringLiteral(n.expression)&&'text' in n.expression&&typeof n.expression.text==='string'?n.expression.text:null)||[];
 let neverFallback=false;
 const fallback=switchNode?.caseBlock.clauses.find(ts.isDefaultClause);
 function checkNever(n){if(ts.isVariableDeclaration(n)&&n.type?.kind===ts.SyntaxKind.NeverKeyword&&n.initializer&&sym(n.initializer)===metadataBinding&&(checker.getTypeAtLocation(n.name).flags&ts.TypeFlags.Never))neverFallback=true;ts.forEachChild(n,checkNever);}
 if(fallback)checkNever(fallback);if(!neverFallback)errors.push('NO_SYMBOL_BOUND_NEVER_FALLBACK');
 if(values.length!==cases.length||new Set(cases).size!==cases.length||values.some(v=>!cases.includes(v)))errors.push('EXHAUSTIVE_CASE_SET_MISMATCH');
 if(unknown.length)errors.push('UNCLASSIFIED_KIND_READ');
 const diagnostics=ts.getPreEmitDiagnostics(program).map(d=>({code:d.code,message:ts.flattenDiagnosticMessageText(d.messageText,' '),file:d.file?path.relative(root,d.file.fileName):null}));
 if(diagnostics.length)errors.push('COMPILER_DIAGNOSTICS');
 return {covered_consumers:[...coveredConsumers].sort(),errors:[...new Set(errors)],classified_record_reads:classified,unknown_kind_reads:unknown,context_reads:contextReads,context_escapes:contextEscapes,request_container_flows:containerFlows,closed_request_container_flows:containerClosure,container_escape_positions:containerEscapePositions,raw_metadata_escapes:rawMetadataEscapes,union:values,cases,diagnostics,closed:errors.length===0,runtime_authorized:false};
}

const result=analyze();
const dependencies=[];
for(const name of ['apps/api/node_modules/typescript/lib/typescript.js','apps/api/node_modules/typescript/package.json','apps/api/node_modules/@nestjs/common/decorators/core/set-metadata.decorator.d.ts','apps/api/node_modules/@nestjs/common/decorators/core/set-metadata.decorator.js','apps/api/node_modules/@nestjs/core/services/reflector.service.d.ts','apps/api/node_modules/@nestjs/core/services/reflector.service.js']){
 const full=path.join(root,name);
 if(!fs.existsSync(full)){result.errors.push('DEPENDENCY_BINDING_MISSING');continue;}
 dependencies.push({path:name,sha256:hash(fs.readFileSync(full))});
}
for(const f of input.files){const full=path.resolve(root,f.path);if(!fs.existsSync(full)||hash(fs.readFileSync(full))!==f.sha256)result.errors.push('SOURCE_BYTES_CHANGED_DURING_PROOF');}
result.closed=result.errors.length===0;
process.stdout.write(JSON.stringify({schema:'NativeMetadataContractObservation/v1',head:input.head,repo:input.repo,contract:input.contract,source_files:input.files,compiler_project:project,typescript:ts.version,dependencies,observation:result})+'\n');
process.exitCode=result.closed?0:3;
