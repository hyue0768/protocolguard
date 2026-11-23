"""AST dependence views, with unchanged full-source context kept for review.

Flow insensitive, intraprocedural may-dependencies. Never executable slices or
soundness claims: reflection, external effects and aliases remain explicit.
"""
import ast
import collections
import json
from pathlib import Path
import subprocess

BASE = Path(__file__).resolve().parent


def python_graph(source, start, end):
    tree = ast.parse(source)
    functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and n.lineno <= start and n.end_lineno >= end]
    if not functions:
        return dict(supported=False, nodes=[], aliases=[], limitations=['no enclosing Python function'], parse_errors=[])
    function = min(functions, key=lambda n: n.end_lineno-n.lineno)
    nodes, aliases = [], []
    limitations = {'calls may mutate memory; no interprocedural proof',
                   'flow-insensitive assignment may-alias; dynamic Python dispatch unresolved'}

    def path(n):
        if isinstance(n, ast.Name):
            return n.id
        if isinstance(n, ast.Attribute):
            root = path(n.value)
            return root+'.'+n.attr if root else None
        if isinstance(n, ast.Subscript):
            root = path(n.value)
            return root+'.*' if root else None

    def collect(n, reads, writes, calls):
        if isinstance(n, ast.stmt):
            return
        if isinstance(n, ast.expr) and path(n):
            (writes if isinstance(n.ctx, (ast.Store, ast.Del)) else reads).add(path(n))
            if isinstance(n, ast.Subscript):
                collect(n.slice, reads, writes, calls)
            return
        if isinstance(n, ast.Call):
            calls.append(ast.unparse(n.func))
        for child in ast.iter_child_nodes(n):
            collect(child, reads, writes, calls)

    def walk(n, controls):
        sid = len(nodes)
        reads, writes, calls = set(), set(), []
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            limitations.add('nested definitions retained as opaque context')
        else:
            for child in ast.iter_child_nodes(n):
                collect(child, reads, writes, calls)
        if isinstance(n, (ast.Assign, ast.AnnAssign)):
            targets = n.targets if isinstance(n, ast.Assign) else [n.target]
            for target in targets:
                if path(target) and path(n.value):
                    aliases.append([path(target), path(n.value)])
        if isinstance(n, ast.AugAssign) and path(n.target):
            reads.add(path(n.target))
        nodes.append(dict(id=sid, line=n.lineno, end=n.end_lineno, kind=type(n).__name__,
                          reads=sorted(reads), writes=sorted(writes), calls=calls,
                          controls=controls, text=ast.get_source_segment(source, n),
                          terminal=isinstance(n, (ast.Return, ast.Raise))))
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            def nested(child):
                if isinstance(child, ast.stmt):
                    walk(child, controls+[sid])
                else:
                    for item in ast.iter_child_nodes(child):
                        nested(item)
            for child in ast.iter_child_nodes(n):
                nested(child)
    for statement in function.body:
        walk(statement, [])
    return dict(supported=True, nodes=nodes, aliases=aliases,
                limitations=sorted(limitations), parse_errors=[])


def may_paths(path, aliases, limit=128):
    """Expand prefix aliases bidirectionally; capped expansion fails closed."""
    seen, queue = {path}, [path]
    while queue:
        item = queue.pop()
        for left, right in aliases:
            for a, b in ((left, right), (right, left)):
                if item == a or item.startswith(a+'.'):
                    value = b+item[len(a):]
                    if value not in seen:
                        seen.add(value);queue.append(value)
                        if len(seen) > limit:
                            raise ValueError('Alias expansion exceeded bound; full source must be retained')
    return seen


def overlap(left, right):
    a, b = left.split('.'), right.split('.')
    return all(x == y or x == '*' or y == '*' for x, y in zip(a, b))


def dependence_view(graph, fields=(), lines=()):
    nodes = graph['nodes']
    if len(nodes)>2000:
        return dict(status='full_context_required', selected_nodes=[n['id'] for n in nodes],
                    reason='AST node bound exceeded; no partial reduction', graph=graph)
    if graph.get('parse_errors') or not graph.get('supported'):
        return dict(status='full_context_required', selected_nodes=[n['id'] for n in nodes],
                    reason='unsupported or parse diagnostics', graph=graph)
    try:
        expanded = {n['id']:dict(reads=set().union(*(may_paths(p, graph['aliases']) for p in n['reads'])) if n['reads'] else set(),
                                writes=set().union(*(may_paths(p, graph['aliases']) for p in n['writes'])) if n['writes'] else set()) for n in nodes}
        criterion = set().union(*(may_paths(p, graph['aliases']) for p in fields)) if fields else set()
    except ValueError as error:
        return dict(status='full_context_required', selected_nodes=[n['id'] for n in nodes], reason=str(error), graph=graph)
    seeds = {n['id'] for n in nodes if any(n['line'] <= line <= n['end'] for line in lines)
             or any(overlap(a,b) for a in criterion for b in expanded[n['id']]['reads']|expanded[n['id']]['writes'])}
    if not seeds:
        return dict(status='full_context_required', selected_nodes=[n['id'] for n in nodes], reason='no matching explicit criterion', graph=graph)
    dependencies = collections.defaultdict(set)
    for n in nodes:
        dependencies[n['id']].update(n['controls'])
        for definition in nodes:
            if any(overlap(a,b) for a in expanded[n['id']]['reads'] for b in expanded[definition['id']]['writes']):
                dependencies[n['id']].add(definition['id'])
    # Calls and terminal effects stay in view: purity/termination is unproven.
    selected = seeds | {n['id'] for n in nodes if n['calls'] or n['terminal']}
    todo = list(selected)
    while todo:
        for sid in dependencies[todo.pop()]-selected:
            selected.add(sid);todo.append(sid)
    return dict(status='bounded_dependency_view_not_sound_slice', criteria=dict(fields=list(fields), lines=list(lines)),
                seeds=sorted(seeds), selected_nodes=sorted(selected),
                omitted_nodes=sorted({n['id'] for n in nodes}-selected),
                dependencies={str(k):sorted(v) for k,v in dependencies.items()}, graph=graph,
                semantic_pruning='not_proven; full original code remains authoritative')


def analyze_document(file, source, start, end, fields=(), lines=()):
    try:
        if file.endswith('.py'):
            graph = python_graph(source, start, end)
        elif file.endswith(('.ts', '.tsx', '.js', '.jsx')):
            result = subprocess.run(['node', str(BASE/'flow_probe.cjs')],
                                    input=json.dumps(dict(file=file, source=source, start=start, end=end)),
                                    text=True, capture_output=True, timeout=30)
            if result.returncode:
                raise ValueError('AST probe failed; source not executed')
            graph = json.loads(result.stdout)
        else:
            return dict(status='full_context_required', reason='no AST dataflow adapter for this language')
        return dependence_view(graph, fields, lines)
    except (SyntaxError, subprocess.TimeoutExpired) as error:
        return dict(status='full_context_required', reason=type(error).__name__)
