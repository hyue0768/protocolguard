"""Offline context closure. No target execution, alias proof or semantic pruning."""
import collections
import re


def closure(symbols, roots, limit=200):
    byid = {s['id']: s for s in symbols}
    if any(root not in byid for root in roots):
        raise ValueError('Unknown root symbol')
    names = collections.defaultdict(list)
    for symbol in symbols:
        names[symbol['name'].split('.')[-1]].append(symbol['id'])
    seen, graph, unresolved, resolutions = set(), {}, {}, {}
    todo = list(roots)
    while todo:
        sid = todo.pop()
        if sid in seen:
            continue
        seen.add(sid)
        if len(seen) > limit:
            raise ValueError('Conservative closure exceeds max-symbols; no partial slice saved')
        edges, missing, decisions = set(), [], []
        for call in byid[sid].get('calls', []):
            # Even a unique short-name match is only a syntactic candidate:
            # receiver dispatch/import identity is not established by this index.
            options = sorted(set(names.get(call.split('.')[-1], [])))
            edges.update(options)
            decisions.append(dict(call=call, candidates=options,
                                  resolution='syntactic_candidates' if options else 'unresolved'))
            missing.append(dict(call=call, candidates=options,
                                reason='receiver/import/alias dispatch unproven' if options else 'no indexed target'))
        graph[sid] = sorted(edges)
        unresolved[sid] = missing
        resolutions[sid] = decisions
        todo.extend(edges - seen)
    return dict(symbol_ids=sorted(seen), call_graph=graph, unresolved=unresolved,
                resolutions=resolutions, dispatch_complete=False)


def field_evidence(code_documents):
    """Lexical member paths for navigation only; never used to discard code."""
    result = []
    pattern = re.compile(r'\b[A-Za-z_$][\w$]*(?:(?:\?\.|\.)[A-Za-z_$][\w$]*)+')
    for document in code_documents:
        for line in document['lines']:
            for match in pattern.finditer(line['text']):
                result.append(dict(file=document['file'], line=line['line'],
                                   column=match.start()+1, expression=match.group(),
                                   classification='lexical_member_path_not_def_use'))
    return result
