"""Offline Python backend: conservative function closure, explicit decisions, no model calls.
Protocol-independent Python source context; not LLVM-equivalent slicing.
"""
import ast
import json
import sqlite3
from pathlib import Path


def index_sources(root):
    root = Path(root).resolve()
    entries = {}
    for path in sorted(root.rglob('*.py')):
        text = path.read_text(encoding='utf-8')
        tree = ast.parse(text, filename=str(path))
        def visit(node, scope=''):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    name = scope + child.name
                    key = f'{path.relative_to(root)}::{name}'
                    entries[key] = dict(path=str(path), name=name, start=child.lineno,
                                        end=child.end_lineno, source=text, node=child)
                    visit(child, name + '.')
                else:
                    visit(child, scope)
        visit(tree)
    return entries


def slice_python(root, rules, decisions, db_path):
    entries = index_sources(root)
    # Resolve same-module names and self methods. Cross-module context is explicit
    # in the decision file; ambiguous dynamic dispatch is recorded, never guessed
    # from a method's globally shared short name (e.g. get/read/to_dict).
    graph, unresolved = {}, {}
    for key, entry in entries.items():
        rel = key.split('::')[0]
        scope = entry['name'].rsplit('.', 1)[0] if '.' in entry['name'] else ''
        targets, missing = set(), set()
        for node in ast.walk(entry['node']):
            if not isinstance(node, ast.Call): continue
            candidate = None
            if isinstance(node.func, ast.Name):
                candidate = f'{rel}::{node.func.id}'
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in ('self','cls'):
                candidate = f'{rel}::{scope}.{node.func.attr}'
            if candidate in entries:
                targets.add(candidate)
            else:
                missing.add(ast.unparse(node.func))
        graph[key], unresolved[key] = targets, sorted(missing)
    reports = []
    with sqlite3.connect(db_path) as db:
        db.execute('CREATE TABLE IF NOT EXISTS rule_code_snippet (rule_desc TEXT PRIMARY KEY, code_snippet TEXT, call_graph TEXT, llm_response TEXT)')
        for rule in rules:
            decision = decisions.get(rule['id'])
            if not decision:
                reports.append({'id':rule['id'], 'status':'pending_handler_decision'})
                continue
            handlers = set(decision['handlers'])
            contexts = set(decision.get('context', []))
            unknown = (handlers | contexts) - entries.keys()
            if unknown:
                raise ValueError(f'Unknown source selectors: {sorted(unknown)}')
            seen, todo = set(), list(handlers)
            while todo:
                k = todo.pop()
                if k in seen:
                    continue
                seen.add(k)
                todo.extend(graph[k] - seen)
            # Full-function retention supplies AST structure and auxiliary/error context.
            # No automatic semantic pruning; explicit contexts are always retained.
            seen |= contexts
            snippet = '\n\n'.join(f"# {k}:{entries[k]['start']}-{entries[k]['end']}\n" +
                '\n'.join(entries[k]['source'].splitlines()[entries[k]['start']-1:entries[k]['end']])
                for k in sorted(seen))
            cg = {k:sorted(graph[k] & seen) for k in sorted(seen)}
            db.execute('INSERT INTO rule_code_snippet VALUES (?, ?, ?, NULL) ON CONFLICT(rule_desc) DO UPDATE SET code_snippet=excluded.code_snippet,call_graph=excluded.call_graph,llm_response=NULL',
                       (rule['rule'], snippet, json.dumps(cg)))
            reports.append({'id':rule['id'], 'status':'source_context_only', 'functions':sorted(seen),
                            'unresolved_calls':{k:unresolved[k] for k in sorted(seen) if unresolved[k]},
                            'limits':'whole functions; local calls only; imported/dynamic calls need explicit context; no semantic verdict'})
    return reports


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--rules", type=Path)
    parser.add_argument("--decisions", type=Path)
    parser.add_argument("--database", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--list-functions", action="store_true")
    args = parser.parse_args()
    if args.list_functions:
        print(json.dumps(sorted(index_sources(args.source)), indent=2))
        return
    if not all([args.rules, args.decisions, args.database, args.report]):
        parser.error("Supply --rules, --decisions, --database and --report, or use --list-functions")
    rules = json.loads(args.rules.read_text())
    decisions = json.loads(args.decisions.read_text())
    if not isinstance(rules, list) or not isinstance(decisions, dict):
        parser.error("rules must be an array and decisions must be an object")
    args.database.parent.mkdir(parents=True, exist_ok=True)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    result = slice_python(args.source, rules, decisions, args.database)
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"database": str(args.database), "report": str(args.report), "rules": len(result)}))


if __name__ == "__main__":
    main()
