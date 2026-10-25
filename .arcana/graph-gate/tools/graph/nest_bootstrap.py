"""Shared, bounded Nest bootstrap/prefix resolution. Unknown syntax is not no-prefix.

Sources and profiles are read from the same Tree (git revision), never from auxiliary
scripts or a repository-global last match. Literal exclusions support exact paths
and RequestMethod names only; path-to-regexp patterns deliberately remain unknown.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import posixpath
import re


def deployable_of(path, deployables):
    roots = [d for d in deployables if d in ("", ".") or path == d or path.startswith(d + "/")]
    return max(roots, key=lambda d: len(d) if d not in ("", ".") else 0) if roots else None


def route_framework(tree, deployable, path, *, repo_nest=False):
    """Attribute the route's framework, not an unrelated sibling's dependencies.

    A Nest decorator/import stays Nest even with hoisted dependencies. Non-JS
    providers and explicitly non-Nest package providers do not take Nest rules.
    Legacy graph-only stand-ins without manifests retain the caller's framework
    evidence; that fallback never changes an explicitly declared framework.
    """
    if not path.endswith(('.ts', '.tsx', '.mts', '.js', '.jsx', '.mjs', '.cjs')):
        return 'non-nest'
    source = tokens(tree.text(path)) if tree.exists(path) else []
    if any(source[i:i + 3] in (['@', 'Controller', '('], ['@', 'WebSocketGateway', '(']) for i in range(len(source) - 2)):
        return 'nest'
    if any(t.startswith(("'@nestjs/", '"@nestjs/')) for t in source):
        return 'nest'
    lead = '' if deployable in ('', '.') else deployable + '/'
    manifest = lead + 'package.json'
    if tree.exists(manifest):
        try:
            package = json.loads(tree.text(manifest))
            dependencies = {**(package.get('dependencies') or {}), **(package.get('devDependencies') or {})}
            return 'nest' if any(k.startswith('@nestjs/') for k in dependencies) else 'non-nest'
        except (ValueError, TypeError, AttributeError):
            return 'unknown'
    return 'nest' if repo_nest else 'non-nest'


def tokens(source):
    """Small lexer: quoted/comment contents can never become executable call sites."""
    pattern = r"//[^\n]*|/\*[\s\S]*?\*/|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|`(?:\\.|[^`\\])*`|[A-Za-z_$][\w$]*|\d+|[^\s]"
    return [m.group() for m in re.finditer(pattern, source) if not m.group().startswith(("//", "/*"))]


def literal(token):
    if len(token) >= 2 and token[0] in "'\"" and token[-1] == token[0] and "\\" not in token:
        return token[1:-1]
    raise ValueError("nonliteral or escaped string")


def split(items, separator=","):
    parts, part, stack = [], [], []
    closing = {"(": ")", "[": "]", "{": "}"}
    for token in items:
        if token in closing:
            stack.append(closing[token])
        elif token in (")", "]", "}"):
            if not stack or stack.pop() != token:
                raise ValueError("unbalanced syntax")
        if token == separator and not stack:
            parts.append(part)
            part = []
        else:
            part.append(token)
    if stack:
        raise ValueError("unbalanced syntax")
    if part:
        parts.append(part)
    return parts


def call_args(ts, start):
    depth = 1
    for end in range(start + 1, len(ts)):
        if ts[end] == "(":
            depth += 1
        elif ts[end] == ")":
            depth -= 1
            if depth == 0:
                return split(ts[start + 1:end])
    raise ValueError("unterminated prefix call")


def _pairs(ts):
    stack, pairs = [], {}
    closing = {'(': ')', '[': ']', '{': '}'}
    for i, token in enumerate(ts):
        if token in closing:
            stack.append(i)
        elif token in closing.values():
            if not stack or closing[ts[stack[-1]]] != token:
                raise ValueError('unbalanced bootstrap syntax')
            start = stack.pop()
            pairs[start] = i
    if stack:
        raise ValueError('unbalanced bootstrap syntax')
    return pairs


def _default_options_parameter(items):
    """One optional boolean-options object with an inert empty-object default.

    An empty call binds this parameter without executing a default expression.
    Destructuring, required fields, callbacks and computed defaults stay unknown.
    """
    if (len(items) < 10 or not re.fullmatch(r'[A-Za-z_$][\w$]*', items[0])
            or items[1:3] != [':', '{'] or items[-4:] != ['}', '=', '{', '}']):
        return False
    fields = split(items[3:-4], ';')
    return bool(fields) and all(len(f) == 4 and re.fullmatch(r'[A-Za-z_$][\w$]*', f[0])
                               and f[1:] == ['?', ':', 'boolean'] for f in fields)


def _functions(ts, pairs):
    """Literal names with empty or bounded inert-default parameters can be entries."""
    functions = []
    for i, token in enumerate(ts):
        if token == 'function':
            p = i + 2 if i + 2 < len(ts) and ts[i + 2] == '(' else i + 1
            if p >= len(ts) or ts[p] != '(' or p not in pairs:
                raise ValueError('unsupported bootstrap function declaration')
            body = pairs[p] + 1
            while body < len(ts) and ts[body] not in ('{', ';', '='):
                body += 1
            if body >= len(ts) or ts[body] != '{':
                raise ValueError('bootstrap function body unresolved')
            parameters = ts[p + 1:pairs[p]]
            name = ts[i + 1] if p == i + 2 and (not parameters or _default_options_parameter(parameters)) else None
            functions.append((body, pairs[body], name, i))
        if ts[i:i + 2] == ['=', '>'] and i + 2 < len(ts) and ts[i + 2] == '{':
            functions.append((i + 2, pairs[i + 2], None, i))
    return functions


def _owner(functions, pos):
    enclosing = [f for f in functions if f[0] < pos < f[1]]
    return min(enclosing, key=lambda f: f[1] - f[0]) if enclosing else None


def _statement_lead(ts, pos):
    start = max((i for i in range(pos) if ts[i] in (';', '{', '}')), default=-1)
    return ts[start + 1:pos]


def _execution_scope(ts, pairs, functions, pos, proven=()):
    """Prove top-level or one unconditionally invoked literal local function."""
    owner = _owner(functions, pos)
    if owner and owner not in proven:
        body, _, name, declaration = owner
        if not name or _owner(functions, declaration):
            raise ValueError('deferred or nested bootstrap configuration')
        invocations = [i for i in range(len(ts) - 2) if ts[i:i + 3] == [name, '(', ')']
                       and not (declaration <= i <= body) and _owner(functions, i) is None]
        if len(invocations) != 1 or _statement_lead(ts, invocations[0]) not in ([], ['void'], ['await']):
            raise ValueError('local bootstrap invocation not proven')
        entry = invocations[0]
        _local_function_binding(ts, owner, entry)
        _no_prior_exit(ts, pairs, functions, entry, None)
        if any(ts[a] == '{' and a < entry < z for a, z in pairs.items()):
            raise ValueError('conditional bootstrap entry')
    # Additional enclosing blocks are not proven unconditional executable scopes.
    if any(ts[a] == '{' and a < pos < z and (not owner or a != owner[0]) for a, z in pairs.items()):
        raise ValueError('conditional or deferred bootstrap configuration')
    _no_prior_exit(ts, pairs, functions, pos, owner)
    return owner


def _no_prior_exit(ts, pairs, functions, pos, scope):
    start = scope[0] + 1 if scope else 0
    if any((ts[i] in ('return', 'throw', 'break', 'continue') or _literal_process_exit(ts, i))
           and _owner(functions, i) == scope
           and not (ts[i] == 'throw' and _primitive_guard_throw(ts, pairs, functions, i, pos, scope))
           for i in range(start, pos)):
        raise ValueError('bootstrap execution may terminate before configuration')


def _local_function_binding(ts, scope, call):
    # No alias, assignment, import, duplicate declaration or callback parameter
    # may replace the exact local declaration used by the one admitted call.
    if [i for i, t in enumerate(ts) if t == scope[2]] != [scope[3] + 1, call]:
        raise ValueError('local bootstrap function binding shadowed or escaped')


def _name_shadowed(ts, name):
    for i, token in enumerate(ts):
        if token == name and (ts[i - 1:i] in (['const'], ['let'], ['var'], ['class'], ['function'])
                              or ts[i + 1:i + 3] == ['=', '>']
                              or ts[i + 1:i + 2] == ['='] and ts[i + 2:i + 3] != ['=']):
            return True
        if token == 'function':
            p = i + 2 if ts[i + 2:i + 3] == ['('] else i + 1
            end = next((j for j in range(p + 1, len(ts)) if ts[j] == ')'), p)
            if name in ts[p + 1:end]:
                return True
        if token in ('const', 'let', 'var') and ts[i + 1:i + 2] in (['{'], ['[']):
            end = next((j for j in range(i + 2, len(ts)) if ts[j] == '='), len(ts))
            if name in ts[i + 1:end]:
                return True
        if token == '(':
            end = next((j for j in range(i + 1, len(ts)) if ts[j] == ')'), len(ts))
            if ts[end + 1:end + 3] == ['=', '>'] and name in ts[i + 1:end]:
                return True
    return False


def _trusted_binding(ts, name, module):
    imports = []
    for i, token in enumerate(ts):
        if token != 'import':
            continue
        end = next((j for j in range(i + 1, len(ts)) if ts[j] == ';'), len(ts))
        part = ts[i + 1:end]
        if name not in part:
            continue
        try:
            at = part.index('from')
            imports.append(part[:at] in ([name], ['{', name, '}']) and literal(part[at + 1]) == module)
        except (ValueError, IndexError):
            imports.append(False)
    # This grammar admits one imported binding and its one runtime use only.
    # Member replacement, aliasing and extra calls cannot inherit import trust.
    return imports == [True] and sum(t == name for t in ts) == 2 and not _name_shadowed(ts, name)


def _factory_declarations(ts, pairs):
    declarations = []
    for i in range(len(ts) - 7):
        if ts[i] not in ('const', 'let') or ts[i + 2:i + 4] != ['=', 'await'] or ts[i + 4:i + 7] != ['NestFactory', '.', 'create']:
            continue
        p, generic = i + 7, None
        if ts[p] == '<':
            if p + 2 >= len(ts) or ts[p + 2:p + 3] != ['>'] or not re.fullmatch(r'[A-Za-z_$][\w$]*', ts[p + 1]):
                raise ValueError('unsupported Nest factory generic')
            generic, p = ts[p + 1], p + 3
        if p >= len(ts) or ts[p] != '(' or p not in pairs:
            raise ValueError('Nest factory call unresolved')
        args = call_args(ts, p)
        if not args or len(args[0]) != 1 or not re.fullmatch(r'[A-Za-z_$][\w$]*', args[0][0]):
            raise ValueError('Nest factory module argument unresolved')
        module_name, module_imports = args[0][0], []
        for j, token in enumerate(ts):
            if token != 'import':
                continue
            end = next((k for k in range(j + 1, len(ts)) if ts[k] == ';'), len(ts))
            part = ts[j + 1:end]
            if module_name not in part or 'from' not in part:
                continue
            at = part.index('from')
            if at + 1 >= len(part):
                raise ValueError('Nest factory module binding import incomplete')
            target = literal(part[at + 1])
            if target.startswith(('./', '../')) and _trusted_binding(ts, module_name, target):
                module_imports.append(target)
        if len(module_imports) != 1:
            raise ValueError('Nest factory module binding not a trusted unshadowed literal local import')
        if generic and not _trusted_binding(ts, 'NestFactory', '@nestjs/core'):
            raise ValueError('generic Nest factory binding not trusted')
        declarations.append((i, generic))
    return declarations


def _direct_return(ts, pairs, functions, declaration, scope):
    returns = [i for i in range(scope[0] + 1, scope[1]) if ts[i] == 'return' and _owner(functions, i) == scope]
    if len(returns) != 1:
        raise ValueError('factory must have one direct return')
    i = returns[0]
    _execution_scope(ts, pairs, functions, i, (scope,))
    if _statement_lead(ts, i) or ts[i:scope[1]] != ['return', ts[declaration + 1], ';']:
        raise ValueError('factory return is conditional, aliased, or not the final statement')
    return i + 1


def _module_entry(ts, pairs, functions, scope):
    name = scope[2]
    invocations = [i for i in range(len(ts) - 2) if ts[i:i + 3] == [name, '(', ')']
                   and not (scope[3] <= i <= scope[0]) and _owner(functions, i) is None]
    if len(invocations) != 1 or _statement_lead(ts, invocations[0]) not in ([], ['void']):
        raise ValueError('bootstrap entry unresolved')
    i = invocations[0]
    _local_function_binding(ts, scope, i)
    _no_prior_exit(ts, pairs, functions, i, None)
    blocks = [a for a, z in pairs.items() if ts[a] == '{' and a < i < z]
    if not blocks:
        return 'unconditional local invocation'
    if len(blocks) != 1:
        raise ValueError('conditional or nested bootstrap entry')
    a = blocks[0]
    if ts[a - 10:a] != ['if', '(', 'require', '.', 'main', '=', '=', '=', 'module', ')'] or ts[a + 1:pairs[a]] != ['void', name, '(', ')', ';']:
        raise ValueError('unrecognized conditional bootstrap entry')
    if ([j for j, t in enumerate(ts) if t == 'require'] != [a - 8]
            or [j for j, t in enumerate(ts) if t == 'module'] != [a - 2]):
        raise ValueError('module entry binding shadowed')
    return 'require.main === module'


def _return_flow(ts, pairs, functions, declarations):
    """One local factory return transferred to one awaited local bootstrap binding."""
    if len(declarations) != 1:
        raise ValueError('multiple or missing Nest applications')
    declaration, generic = declarations[0]
    factory = _owner(functions, declaration)
    if not factory or not any(ts[i] == 'return' and _owner(functions, i) == factory for i in range(factory[0] + 1, factory[1])):
        return None
    if ts[declaration] != 'const' or not factory[2] or ts[factory[3] - 1] != 'async' or not _trusted_binding(ts, 'NestFactory', '@nestjs/core'):
        raise ValueError('local factory binding not trusted')
    returned = _direct_return(ts, pairs, functions, declaration, factory)
    callers = [i for i in range(len(ts) - 6) if ts[i:i + 1] == ['const'] and ts[i + 2:i + 7] == ['=', 'await', factory[2], '(', ')']]
    calls = [i for i in range(len(ts) - 1) if ts[i:i + 2] == [factory[2], '('] and not (factory[3] <= i <= factory[0])]
    if len(callers) != 1 or calls != [callers[0] + 4]:
        raise ValueError('same-file factory caller not uniquely awaited')
    caller_decl = callers[0]
    caller = _owner(functions, caller_decl)
    if not caller or caller == factory or not caller[2] or ts[caller[3] - 1] != 'async':
        raise ValueError('local caller scope unresolved')
    _local_function_binding(ts, factory, caller_decl + 4)
    entry = _module_entry(ts, pairs, functions, caller)
    for pos, scope in ((declaration, factory), (caller_decl, caller)):
        _execution_scope(ts, pairs, functions, pos, (factory, caller))
        if _statement_lead(ts, pos):
            raise ValueError('conditional application binding')
    return {'scopes': (factory, caller), 'return': returned, 'caller_declaration': caller_decl,
            'factory_scope': factory, 'caller_scope': caller,
            'proof': {'factory': factory[2], 'caller': caller[2], 'entry': entry,
                      'generic_type': generic, 'receiver_transfer': {'factory': ts[declaration + 1], 'caller': ts[caller_decl + 1]},
                      'assumptions': []}}


def _static_register(ts, pairs, receiver):
    args = call_args(ts, receiver + 3)
    if len(args) != 2 or args[0] not in (['fastifyStatic'], ['fastifyStatic', 'as', 'never']) or not _trusted_binding(ts, 'fastifyStatic', '@fastify/static'):
        raise ValueError('register plugin not the trusted static import')
    options = args[1]
    if options[-2:] == ['as', 'never']:
        options = options[:-2]
    if options[:1] != ['{'] or options[-1:] != ['}'] or ts[receiver] in options:
        raise ValueError('static register options not literal or capture application')
    for field_tokens in split(options[1:-1]):
        if len(field_tokens) < 3 or field_tokens[1] != ':' or not re.fullmatch(r'[A-Za-z_$][\w$]*', field_tokens[0]):
            raise ValueError('static register option field unresolved')
        value = field_tokens[2:]
        if len(value) == 1 and (re.fullmatch(r'[A-Za-z_$][\w$]*|\d+', value[0]) or value[0][:1] in ("'", '"')):
            continue
        if (value[:2] == ['join', '('] and value[-1:] == [')']
                and _trusted_binding(ts, 'join', 'node:path')):
            args = split(value[2:-1])
            if args and args[0] == ['__dirname']:
                for arg in args[1:]:
                    if len(arg) != 1:
                        raise ValueError('static path option unresolved')
                    literal(arg[0])
                continue
        raise ValueError('static register callback/options unresolved')


def _literal_boolean_options(items, keys):
    if items[:1] != ['{'] or items[-1:] != ['}']:
        return False
    fields = split(items[1:-1])
    if any(not f for f in fields):
        return False
    return (bool(fields) and len({f[0] for f in fields}) == len(fields)
            and all(len(f) == 3 and f[0] in keys and f[1] == ':'
                    and f[2] in ('true', 'false') for f in fields))


def _literal_cors_options(items):
    if items[:1] != ['{'] or items[-1:] != ['}']:
        return False
    fields = split(items[1:-1])
    if any(not f for f in fields):
        return False
    names = [f[0] for f in fields]
    if len(names) != len(set(names)):
        return False
    for f in fields:
        if len(f) < 3 or f[1] != ':':
            return False
        value = f[2:]
        if f[0] == 'credentials' and value in (['true'], ['false']):
            continue
        if f[0] == 'origin':
            if len(value) == 1:
                literal(value[0])
                continue
            if len(value) == 8 and value[:5] == ['process', '.', 'env', '.', value[4]] and value[5:7] == ['?', '?']:
                literal(value[7])
                continue
        if f[0] in ('methods', 'allowedHeaders') and value[:1] == ['['] and value[-1:] == [']']:
            for item in split(value[1:-1]):
                if len(item) != 1:
                    return False
                text = literal(item[0])
                if f[0] == 'methods' and text not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
                    return False
            continue
        return False
    return bool(fields)


def _route_neutral_configuration(ts, pairs, receiver):
    """Bounded Nest/Express method-effect contracts, never runtime/canary proof."""
    method = ts[receiver + 2]
    if method == 'getHttpAdapter':
        expected = ['.', 'getHttpAdapter', '(', ')', '.', 'getInstance', '(', ')', '.', 'set',
                    '(', "'query parser'", ',', "'extended'", ')', ';']
        return ts[receiver + 1:receiver + 17] == expected
    args = call_args(ts, receiver + 3)
    if method == 'use':
        return args == [['helmet', '(', ')']] and _trusted_binding(ts, 'helmet', 'helmet')
    if method == 'useGlobalPipes':
        return (len(args) == 1 and args[0][:3] == ['new', 'ValidationPipe', '(']
                and args[0][-1:] == [')']
                and _trusted_binding(ts, 'ValidationPipe', '@nestjs/common')
                and _literal_boolean_options(args[0][3:-1], {'whitelist', 'forbidNonWhitelisted', 'transform'}))
    if method == 'enableCors':
        return len(args) == 1 and not _name_shadowed(ts, 'process') and _literal_cors_options(args[0])
    return False


def _snapshot_shape(ts, pairs, functions, name, creation, scope):
    """An immutable member snapshot whose mismatch throws before app creation.

    This proves primitive custody, not the provider's implementation or runtime
    fitness. Mutable configuration members never inherit this proof.
    """
    bindings = [j for j in range(creation) if ts[j:j + 3] == ['const', name, '=']]
    if len(bindings) != 1:
        return None
    j = bindings[0]
    if (_owner(functions, j) != scope or _statement_lead(ts, j)
            or len(ts[j + 3:j + 7]) != 4 or ts[j + 4] != '.' or ts[j + 6] != ';'
            or any(not re.fullmatch(r'[A-Za-z_$][\w$]*', ts[k]) for k in (j + 3, j + 5))):
        return None
    guard = j + 7
    part = ts[guard:guard + 18]
    if len(part) != 18 or part[7] not in ("'string'", '"string"', "'number'", '"number"'):
        return None
    expected = ['if', '(', 'typeof', name, '!', '=', '=', part[7], ')', '{',
                'throw', 'new', 'Error', '(', part[14], ')', ';', '}']
    if (part != expected or guard + 18 > creation or pairs.get(guard + 1) != guard + 8
            or pairs.get(guard + 9) != guard + 17):
        return None
    literal(part[14])
    if any(ts[a] == '{' and a < j < z and (not scope or a != scope[0]) for a, z in pairs.items()):
        return None
    if _name_shadowed(ts, 'Error') or any(t == 'import' and 'Error' in ts[i:next((k for k in range(i, len(ts)) if ts[k] == ';'), len(ts))] for i, t in enumerate(ts)):
        return None
    masked = list(ts)
    masked[j + 1] = '__proven_snapshot_binding__'
    updates = tuple(list(op) for op in ('++', '--', '+=', '-=', '*=', '/=', '%=',
                    '&=', '|=', '^=', '**=', '<<=', '>>=', '>>>=', '&&=', '||=', '??='))
    if _name_shadowed(masked, name) or any(
            t == name and i != j + 1 and
            (any(ts[i + 1:i + 1 + len(op)] == op for op in updates)
             or ts[max(0, i - 2):i] in (['+', '+'], ['-', '-']))
            for i, t in enumerate(ts)):
        return None
    return j, guard, literal(part[7])


def _primitive_guard_throw(ts, pairs, functions, throw, limit, scope):
    # A failed primitive guard cannot reach configuration; this proves syntax
    # conditional on reaching it, never successful initialization or runtime.
    guard = throw - 10
    if guard < 0 or ts[guard:guard + 3] != ['if', '(', 'typeof']:
        return False
    shape = _snapshot_shape(ts, pairs, functions, ts[guard + 3], limit, scope)
    return bool(shape and shape[1] == guard)


def _guarded_snapshot(ts, pairs, functions, name, creation, scope):
    shape = _snapshot_shape(ts, pairs, functions, name, creation, scope)
    if not shape:
        return None
    binding, guard, primitive = shape
    _execution_scope(ts, pairs, functions, binding)
    _execution_scope(ts, pairs, functions, guard)
    return primitive


def _multipart_register(ts, pairs, functions, receiver, creation, scope):
    """Trusted multipart parser registration; static prefix method-effect only."""
    args = call_args(ts, receiver + 3)
    if (len(args) != 2 or args[0] not in (['multipart'], ['multipart', 'as', 'never'])
            or not _trusted_binding(ts, 'multipart', '@fastify/multipart')):
        return False
    options = args[1]
    if options[:1] != ['{'] or options[-1:] != ['}']:
        return False
    outer = split(options[1:-1])
    if len(outer) != 1 or outer[0][:2] != ['limits', ':']:
        return False
    limits = outer[0][2:]
    if limits[:1] != ['{'] or limits[-1:] != ['}']:
        return False
    fields = split(limits[1:-1])
    if len(fields) != 3 or any(len(f) != 3 or f[1] != ':' for f in fields):
        return False
    values = {f[0]: f[2] for f in fields}
    return (set(values) == {'fileSize', 'files', 'fields'}
            and all(re.fullmatch(r'\d+', values[k]) and int(values[k]) > 0 for k in ('files', 'fields'))
            and _guarded_snapshot(ts, pairs, functions, values['fileSize'], creation, scope) == 'number')


def _app_uses(ts, pairs, functions, app, declaration, scope, flow=None):
    """Only direct recognized receiver calls preserve the local application's identity."""
    limit = scope[1] if scope else len(ts)
    proven = flow['scopes'] if flow else ()
    listen = []
    neutral = []
    for i in range(declaration + 2, limit):
        if ts[i] != app:
            continue
        if _owner(functions, i) != scope:
            raise ValueError('application captured by an unproven function')
        if flow and i == flow['return']:
            continue
        member = ts[i + 1:i + 4]
        if flow and member == ['.', 'register', '('] and scope == flow['factory_scope']:
            _execution_scope(ts, pairs, functions, i, proven)
            if _statement_lead(ts, i) != ['await']:
                raise ValueError('conditional static registration')
            _static_register(ts, pairs, i)
            flow['proof']['assumptions'] = ['static register method-effect assumption']
            continue
        if member == ['.', 'register', '('] and not flow:
            _execution_scope(ts, pairs, functions, i)
            if (_statement_lead(ts, i) != ['await']
                    or not _multipart_register(ts, pairs, functions, i, declaration, scope)):
                raise ValueError('multipart registration binding/options not proven')
            neutral.append('trusted @fastify/multipart route-neutral method-effect assumption')
            continue
        if flow and member == ['.', 'getHttpServer', '('] and scope == flow['caller_scope']:
            lead = _statement_lead(ts, i)
            if (not listen or ts[i + 3:i + 10] != ['(', ')', '.', 'address', '(', ')', ';']
                    or len(lead) != 3 or lead[0] != 'const' or lead[2] != '='):
                raise ValueError('server observation not proven post-listen address()')
            continue
        if member not in (['.', 'setGlobalPrefix', '('], ['.', 'listen', '(']):
            if (len(member) == 3 and member[0] == '.' and member[2] == '('
                    and member[1] in ('getHttpAdapter', 'use', 'useGlobalPipes', 'enableCors')
                    and _route_neutral_configuration(ts, pairs, i)):
                _execution_scope(ts, pairs, functions, i, proven)
                if _statement_lead(ts, i):
                    raise ValueError('conditional application configuration')
                neutral.append('Nest/Express route-neutral method-effect assumption: ' + member[1])
                continue
            raise ValueError('application escaped, aliased, or unknown receiver use')
        _execution_scope(ts, pairs, functions, i, proven)
        if _statement_lead(ts, i) not in ([], ['await']):
            raise ValueError('conditional application method expression')
        if ts[i + 2] == 'listen':
            if flow and _statement_lead(ts, i) != ['await']:
                raise ValueError('bootstrap listen not awaited')
            listen.append(i)
    if flow and scope == flow['caller_scope'] and len(listen) != 1:
        raise ValueError('one unconditional bootstrap listen not proven')
    return neutral


@dataclass
class Bootstrap:
    root_file: str | None = None
    prefix: str | None = None
    exclusions: list[tuple[str, str | None]] = field(default_factory=list)
    complete: bool = False
    reason: str = "bootstrap not resolved"
    proof: dict | None = None

    def effective_prefix(self, method, path):
        route = path.strip("/")
        matching = [m for p, m in self.exclusions if route == p]
        if method == 'ALL' and matching and not any(m in (None, 'ALL') for m in matching):
            raise ValueError('ALL route has method-specific exclusion; no single effective prefix')
        excluded = any(route == p and (m is None or m == method or m == "ALL") for p, m in self.exclusions)
        return None if excluded else self.prefix

    def evidence(self):
        evidence = {"root_module_file": self.root_file, "global_prefix": self.prefix,
                "exclusions": [{"path": p, "method": m} for p, m in self.exclusions],
                "complete": self.complete, "reason": self.reason}
        if self.proof:
            evidence['proof'] = self.proof
        return evidence


def _exclusions(options):
    if not options or options[0] != "{" or options[-1] != "}":
        raise ValueError("nonliteral prefix options")
    fields = split(options[1:-1])
    if len(fields) != 1 or fields[0][:3] != ["exclude", ":", "["] or fields[0][-1] != "]":
        raise ValueError("unsupported prefix options")
    out = []
    for item in split(fields[0][3:-1]):
        method = None
        if len(item) == 1:
            path = literal(item[0])
        elif item[:1] == ["{"] and item[-1:] == ["}"]:
            attrs = split(item[1:-1])
            pairs = {a[0]: a[2:] for a in attrs if len(a) >= 3 and a[1] == ":"}
            if len(attrs) != 2 or set(pairs) != {"path", "method"} or len(pairs["path"]) != 1:
                raise ValueError("unsupported exclusion object")
            path = literal(pairs["path"][0])
            mt = pairs["method"]
            if len(mt) != 3 or mt[:2] != ["RequestMethod", "."] or mt[2] not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ALL"}:
                raise ValueError("unknown exclusion method")
            method = mt[2]
        else:
            raise ValueError("nonliteral exclusion")
        if re.search(r"[^\w/.-]", path, re.ASCII):
            raise ValueError("unsupported exclusion path pattern")
        out.append((path.strip("/"), method))
    return out


def _primitive_module(provider, pairs):
    """No startup execution: literal constants and lazy function definitions only."""
    i = 0
    while i < len(provider):
        if provider[i] == 'export':
            i += 1
        if provider[i:i + 1] == ['const']:
            if (provider[i + 2:i + 3] != ['='] or provider[i + 4:i + 5] != [';']
                    or not re.fullmatch(r'[A-Za-z_$][\w$]*', provider[i + 1])):
                raise ValueError('diagnostic provider initializer unresolved')
            value = provider[i + 3]
            if not re.fullmatch(r'\d+', value):
                literal(value)
            i += 5
            continue
        if provider[i:i + 1] == ['function']:
            if provider[i + 2:i + 3] != ['('] or i + 2 not in pairs:
                raise ValueError('diagnostic provider function unresolved')
            close = pairs[i + 2]
            start = close + 3
            if (provider[close + 1:close + 2] != [':']
                    or provider[start:start + 1] != ['{'] or start not in pairs):
                raise ValueError('diagnostic provider function signature unresolved')
            i = pairs[start] + 1
            continue
        raise ValueError('diagnostic provider startup effects unresolved')


def _primitive_import(tree, root, ts, name, kind):
    """Resolve a literal relative named import and prove its entire small body."""
    imports = []
    for i, token in enumerate(ts):
        if token != 'import':
            continue
        end = next((j for j in range(i + 1, len(ts)) if ts[j] == ';'), len(ts))
        part = ts[i + 1:end]
        if name not in part:
            continue
        if ('as' in part or part[:1] != ['{'] or 'from' not in part
                or _name_shadowed(ts, name)):
            raise ValueError('diagnostic import binding unresolved')
        imports.append(literal(part[part.index('from') + 1]))
    if len(imports) != 1 or not imports[0].startswith('.'):
        raise ValueError('diagnostic primitive provider unresolved')
    path = posixpath.normpath(posixpath.join(posixpath.dirname(root), imports[0]))
    candidates = [path, path[:-3] + '.ts'] if path.endswith('.js') else [path, path + '.ts']
    paths = [p for p in candidates if tree.exists(p)]
    if len(paths) != 1:
        raise ValueError('diagnostic primitive provider missing/ambiguous')
    provider = tokens(tree.text(paths[0]))
    if (any(t in ('eval', 'Function', 'Reflect', 'Proxy', 'globalThis', 'global', 'Object') for t in provider)
            or sum(t == 'process' for t in provider) != 1):
        raise ValueError('diagnostic primitive provider dynamic')
    pairs = _pairs(provider)
    _primitive_module(provider, pairs)
    definitions = [i for i in range(len(provider)) if provider[i:i + 3] == ['function', name, '(']]
    if len(definitions) != 1 or sum(t == name for t in provider) != 1:
        raise ValueError('diagnostic primitive provider binding replaced')
    i = definitions[0]
    close = pairs[i + 2]
    signature = provider[i + 3:close]
    start = close + 3
    if provider[close + 1:close + 3] != [':', kind] or provider[start:start + 1] != ['{']:
        raise ValueError('diagnostic primitive signature unsupported')
    body = provider[start + 1:pairs[start]]
    if kind == 'string':
        env = signature[0] if signature else ''
        if signature != [env, ':', 'NodeJS', '.', 'ProcessEnv', '=', 'process', '.', 'env']:
            raise ValueError('diagnostic string input unsupported')
        if len(body) != 27:
            raise ValueError('diagnostic string body unsupported')
        local, key = body[1], body[6]
        expected = ['const', local, '=', '(', env, '.', key, '?', '?', body[9], ')', '.', 'trim', '(', ')', ';',
                    'return', local, '.', 'length', '>', '0', '?', local, ':', body[25], ';']
        # Token counts are checked by exact whole-body comparison, never partial matching.
        if body != expected:
            raise ValueError('diagnostic string body unsupported')
        literal(body[9]); literal(body[25])
    elif kind == 'boolean':
        if len(signature) != 3 or signature[1:] != [':', 'string']:
            raise ValueError('diagnostic boolean input unsupported')
        parameter = signature[0]
        if (len(body) != 14 or body[:5] != ['return', parameter, '=', '=', '=']
                or body[6:11] != ['|', '|', parameter, '=', '=']
                or body[11] != '=' or body[-1] != ';'):
            raise ValueError('diagnostic boolean body unsupported')
        for constant in (body[5], body[12]):
            declarations = [j for j in range(len(provider)) if provider[j:j + 3] == ['const', constant, '=']]
            assignments = [j for j, t in enumerate(provider) if t == constant and provider[j + 1:j + 2] == ['=']]
            if len(declarations) != 1 or assignments != [declarations[0] + 1]:
                raise ValueError('diagnostic boolean constant replaced')
            j = declarations[0]
            if provider[j + 4:j + 5] != [';']:
                raise ValueError('diagnostic boolean constant nonliteral')
            literal(provider[j + 3])
    else:
        raise ValueError('diagnostic primitive kind unsupported')


def _diagnostic_value(tree, root, ts, expression):
    if len(expression) == 1:
        if not re.fullmatch(r'\d+', expression[0]):
            literal(expression[0])
        return
    if (len(expression) == 3 and expression[1:] == ['(', ')']
            and re.fullmatch(r'[A-Za-z_$][\w$]*', expression[0])):
        _primitive_import(tree, root, ts, expression[0], 'string')
        return
    if (len(expression) == 13 and expression[:6] == ['parseInt', '(', 'process', '.', 'env', '.']
            and expression[7:9] == ['?', '?'] and expression[10:] == [',', '10', ')']):
        literal(expression[9])
        if _name_shadowed(ts, 'parseInt') or _name_shadowed(ts, 'process'):
            raise ValueError('diagnostic numeric builtin replaced')
        return
    raise ValueError('diagnostic value not proven primitive')


def _literal_process_exit(ts, pos):
    """One unshadowed native termination statement; never a runtime success proof."""
    return (ts[pos:pos + 4] == ['process', '.', 'exit', '(']
            and len(ts) > pos + 5 and re.fullmatch(r'\d+', ts[pos + 4]) is not None
            and 0 <= int(ts[pos + 4]) <= 255 and ts[pos + 5] == ')'
            and ts[pos + 6:pos + 7] in ([], [';'], ['}'])
            and not _statement_lead(ts, pos) and not _name_shadowed(ts, 'process'))


def _promise_builtin_untouched(ts, pairs, functions):
    """Permit bounded erased return types, never Promise values or prototype aliases."""
    for i, token in enumerate(ts):
        previous = ts[i - 1] if i else ''
        if (previous == '.' and token in ('constructor', 'prototype', '__proto__')
                or token == '[' and (previous in (')', ']')
                    or re.fullmatch(r'[A-Za-z_$][\w$]*', previous)
                    and previous not in ('return', 'throw', 'await', 'void', 'typeof', 'new')
                    or ts[max(0, i - 2):i] == ['?', '.'])):
            return False
    type_positions = set()
    for body, _, _, declaration in functions:
        if ts[declaration] != 'function':
            continue
        parameters = declaration + (2 if ts[declaration + 2:declaration + 3] == ['('] else 1)
        close = pairs.get(parameters)
        if close is None:
            continue
        annotation = ts[close + 1:body]
        if (len(annotation) == 5 and annotation[:3] == [':', 'Promise', '<']
                and re.fullmatch(r'[A-Za-z_$][\w$]*', annotation[3])
                and annotation[4] == '>'):
            type_positions.add(close + 2)
    return all(token != 'Promise' or i in type_positions for i, token in enumerate(ts))


def _failure_handler_exit(ts, pos, pairs, functions, declarations):
    """Bounded async entry rejection handler only; do not infer helper call reachability."""
    scope = _owner(functions, pos)
    if (not scope or scope[2] or ts[scope[3]:scope[3] + 2] != ['=', '>']
            or not _promise_builtin_untouched(ts, pairs, functions)):
        return False
    for call in range(scope[3]):
        if (ts[call + 1:call + 6] != ['(', ')', '.', 'catch', '(']
                or pairs.get(call + 5) != scope[1] + 1
                or ts[scope[1] + 2:scope[1] + 3] not in ([], [';'])
                or _statement_lead(ts, call) or _owner(functions, call)):
            continue
        entries = [f for f in functions if f[2] == ts[call] and not _owner(functions, f[3])
                   and ts[f[3] - 1:f[3]] == ['async']]
        if len(entries) != 1 or [i for i, t in enumerate(ts) if t == 'catch'] != [call + 4]:
            continue
        parameters = ts[call + 6:scope[3]]
        if (parameters[:1] == ['('] and parameters[-1:] == [')']):
            parameters = parameters[1:-1]
        if (len(parameters) != 1 or not re.fullmatch(r'[A-Za-z_$][\w$]*', parameters[0])
                or not declarations
                or any(_owner(functions, d) != entries[0] for d, _ in declarations)):
            continue
        try:
            _local_function_binding(ts, entries[0], call)
        except ValueError:
            continue
        return True
    return False


def _readonly_process_env(ts, pos, pairs):
    """Exact member reads only; mutation, deletion, whole-object aliases stay unknown."""
    lead = _statement_lead(ts, pos)
    # Assignment can target a parenthesized member or any position in a destructuring
    # pattern. Check the operator after EACH containing delimiter, not only the field.
    ends = [pos + 5] + [close + 1 for start, close in pairs.items() if start < pos < close]
    for end in ends:
        suffix = ts[end:end + 4]
        if (suffix[:1] in (['='], ['of'], ['in']) or suffix[:2] in (['+', '+'], ['-', '-'])
                or suffix and suffix[0] in '+-*/%&|^<>?' and '=' in suffix):
            return False
    return (ts[pos + 1:pos + 4] == ['.', 'env', '.']
            and len(ts) > pos + 4 and re.fullmatch(r'[A-Za-z_$][\w$]*', ts[pos + 4]) is not None
            and not _name_shadowed(ts, 'process') and 'delete' not in lead
            and not any(lead[i:i + 2] in (['+', '+'], ['-', '-']) for i in range(len(lead))))


def _diagnostic_receiver(ts, pairs, functions, call, scope):
    receiver = ts[call]
    if receiver == 'console':
        return (not _name_shadowed(ts, 'console') and all(
            ts[j:j + 4] == ['console', '.', 'log', '(']
            for j, token in enumerate(ts) if token == 'console'))
    if not _trusted_binding(ts, 'Logger', '@nestjs/common'):
        return False
    bindings = [j for j in range(call) if ts[j:j + 3] == ['const', receiver, '=']]
    if len(bindings) != 1:
        return False
    j = bindings[0]
    close = pairs.get(j + 5)
    if (ts[j + 3:j + 6] != ['new', 'Logger', '('] or close != j + 7
            or ts[close + 1:close + 2] != [';'] or _owner(functions, j) != scope
            or _statement_lead(ts, j)):
        return False
    literal(ts[j + 6])
    _execution_scope(ts, pairs, functions, j)
    return all(k == j + 1 or (ts[k - 1:k] in (['{'], [',']) and ts[k + 1:k + 2] == [':'])
               or ts[k:k + 4] == [receiver, '.', 'log', '(']
               and _owner(functions, k) == scope
               for k, token in enumerate(ts) if token == receiver)


def _diagnostic_templates(tree, root, ts, pairs, functions, declarations):
    """Only post-listen console output of proven primitive locals is inert.

    Identifier coercion can execute user code for objects. Unproven imported functions,
    object/getter values, aliases, eval and nested templates remain unknown.
    This proves prefix syntax only, not successful bootstrap or runtime fitness.
    """
    if any(t in ('eval', 'Function', 'Reflect', 'Proxy', 'globalThis', 'global', 'Object') for t in ts):
        raise ValueError('dynamic bootstrap reflection not proven')
    for i, t in enumerate(ts):
        if t == 'process':
            if _literal_process_exit(ts, i):
                if not _failure_handler_exit(ts, i, pairs, functions, declarations):
                    raise ValueError('bootstrap termination outside proven failure handler')
            elif not _readonly_process_env(ts, i, pairs):
                raise ValueError('bootstrap environment binding not read-only')
        if t == 'parseInt' and ts[i + 1:i + 2] != ['(']:
            raise ValueError('bootstrap numeric builtin binding replaced')
    for i, token in enumerate(ts):
        if not (token.startswith('`') and '${' in token):
            continue
        names = re.findall(r'\$\{([A-Za-z_$][\w$]*)\}', token)
        residue = re.sub(r'\$\{([A-Za-z_$][\w$]*)\}', '', token)
        if not names or '${' in residue or '\\' in token:
            raise ValueError('bootstrap template interpolation not proven')
        calls = [j for j in range(i) if ts[j + 1:j + 4] == ['.', 'log', '(']
                 and pairs.get(j + 3, -1) > i]
        if len(calls) != 1 or not _diagnostic_receiver(ts, pairs, functions, calls[0], _owner(functions, calls[0])):
            raise ValueError('diagnostic receiver not proven')
        call = calls[0]
        arguments = ts[call + 4:pairs[call + 3]]
        if arguments[-1:] == [',']:
            arguments = arguments[:-1]
        tail = arguments[1:]
        if tail:
            if (len(tail) != 11 or tail[:2] != ['+', '('] or tail[3:4] != ['(']
                    or tail[5:8] != [')', '?', tail[7]] or tail[8:9] != [':'] or tail[-1:] != [')']):
                raise ValueError('diagnostic expression not proven inert')
            if tail[4] not in names:
                raise ValueError('diagnostic boolean argument not proven scalar')
            _primitive_import(tree, root, ts, tail[2], 'boolean')
            literal(tail[7]); literal(tail[9])
        if _statement_lead(ts, call):
            raise ValueError('diagnostic expression not proven inert')
        scope = _owner(functions, call)
        starts = [d for d, _ in declarations if _owner(functions, d) == scope]
        if len(starts) != 1:
            raise ValueError('diagnostic application scope not proven')
        app = ts[starts[0] + 1]
        listens = [j for j in range(starts[0], call) if ts[j:j + 4] == [app, '.', 'listen', '(']
                   and _statement_lead(ts, j) == ['await'] and _owner(functions, j) == scope]
        if len(listens) != 1:
            raise ValueError('diagnostic not proven post-listen')
        for name in names:
            if _guarded_snapshot(ts, pairs, functions, name, starts[0], scope):
                continue
            bindings = [j for j in range(starts[0], call) if ts[j:j + 3] == ['const', name, '=']
                        and _owner(functions, j) == scope]
            if len(bindings) != 1:
                raise ValueError('diagnostic scalar binding not proven')
            j = bindings[0]
            end = next((k for k in range(j + 3, call) if ts[k] == ';'), call)
            if _statement_lead(ts, j):
                raise ValueError('diagnostic binding conditional')
            _diagnostic_value(tree, root, ts, ts[j + 3:end])
            # Other declarations/assignments of this name may replace a binding.
            uses = [k for k, t in enumerate(ts) if t == name and
                    (ts[k - 1:k] in (['const'], ['let'], ['var'], ['function'], ['class'])
                     or ts[k + 1:k + 2] == ['='])]
            if uses != [j + 1]:
                raise ValueError('diagnostic scalar binding replaced')


def resolve(tree, deployable, deployables, profile=None):
    """Resolve an explicit root or one unique default, with exact deployable containment."""
    result = Bootstrap()
    try:
        if profile is None:
            profile = json.loads(tree.text(".arcana/verify.json")) if tree.exists(".arcana/verify.json") else {}
        if not isinstance(profile, dict) or profile.get('_invalid_bootstrap_profile'):
            raise ValueError('invalid bootstrap profile')
        if 'deployables' in profile and not isinstance(profile['deployables'], dict):
            raise ValueError('invalid deployables profile')
        entry = (profile.get("deployables") or {}).get(deployable, {})
        if "root_module_file" in entry:
            root = entry["root_module_file"]
            if not isinstance(root, str) or not root or root.startswith("/") or posixpath.normpath(root) != root:
                raise ValueError("invalid explicit bootstrap path")
        else:
            lead = "" if deployable in ("", ".") else deployable + "/"
            candidates = [lead + "src/main" + ext for ext in (".ts", ".mts") if tree.exists(lead + "src/main" + ext)]
            if len(candidates) != 1:
                raise ValueError("missing or ambiguous default bootstrap")
            root = candidates[0]
        if not tree.exists(root) or deployable_of(root, deployables) != deployable:
            raise ValueError("explicit bootstrap missing or outside deployable")
        result.root_file = root
        ts = tokens(tree.text(root))
        pairs = _pairs(ts)
        functions = _functions(ts, pairs)
        declarations = _factory_declarations(ts, pairs)
        _diagnostic_templates(tree, root, ts, pairs, functions, declarations)
        app_declarations = [i for i, _ in declarations]
        flow = _return_flow(ts, pairs, functions, declarations) if declarations else None
        if flow:
            app_declarations.append(flow['caller_declaration'])
            result.proof = flow['proof']
        proven = flow['scopes'] if flow else ()
        apps = [ts[i + 1] for i in app_declarations]
        for declaration in app_declarations:
            scope = _execution_scope(ts, pairs, functions, declaration, proven)
            if _statement_lead(ts, declaration):
                raise ValueError('conditional application creation')
            assumptions = _app_uses(ts, pairs, functions, ts[declaration + 1], declaration, scope, flow)
            if assumptions:
                if result.proof is None:
                    result.proof = {'scope': 'static prefix/exclusions only', 'assumptions': []}
                result.proof.setdefault('assumptions', []).extend(assumptions)
        calls = [i for i in range(len(ts) - 1) if ts[i:i + 2] == ["setGlobalPrefix", "("]]
        if len(calls) > 1:
            raise ValueError("multiple prefix calls in selected bootstrap")
        if calls:
            i = calls[0]
            if i < 2 or ts[i - 1] != ".":
                raise ValueError("unresolved prefix receiver")
            receivers = [d for d in app_declarations if ts[d + 1] == ts[i - 2] and _owner(functions, d) == _owner(functions, i)]
            if apps and len(receivers) != 1:
                raise ValueError('prefix receiver is not the unique Nest application')
            _execution_scope(ts, pairs, functions, i, proven)
            if _statement_lead(ts, i - 2) not in ([], ['await']):
                raise ValueError('conditional prefix expression')
            args = call_args(ts, i + 1)
            if not 1 <= len(args) <= 2 or len(args[0]) != 1:
                raise ValueError("dynamic prefix")
            prefix = literal(args[0][0]).strip("/")
            result.prefix = "/" + prefix if prefix else None
            if len(args) == 2:
                result.exclusions = _exclusions(args[1])
        elif len(declarations) != 1:
            raise ValueError('selected root does not directly create one Nest application; forwarding unresolved')
        # Even indirect/computed use must not masquerade as an absent prefix call.
        if sum(t == "setGlobalPrefix" or t.strip("'\"") == "setGlobalPrefix" for t in ts) != len(calls):
            raise ValueError("unresolved prefix access")
        result.complete = True
        result.reason = "literal prefix/exclusions in selected bootstrap" if calls else "no prefix call in selected bootstrap"
    except (ValueError, TypeError, AttributeError) as exc:
        result.reason = str(exc)
    return result
