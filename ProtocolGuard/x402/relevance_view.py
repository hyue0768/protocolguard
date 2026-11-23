"""Validate advisory model relevance labels; never discard original context."""


MAX_ADVISORY_LABELS = 48


def advisory_plan(views):
    """Bound optional output work before any API request; source is never cut.

    The current wire format requires a reason and evidence for EVERY node,
    including protected nodes. Avoid that request if it cannot propose any
    focus changes or would have unbounded output relative to its fixed cap.
    """
    total=0;candidates=0;opaque=0
    for entry in views:
        view=entry['view'];nodes=view.get('graph',{}).get('nodes',[])
        total+=len(nodes)
        if not nodes:opaque+=1
        selected=set(view.get('selected_nodes',[]))
        for node in nodes:
            if (view.get('status')=='bounded_dependency_view_not_sound_slice'
                    and node['id'] not in selected and not node['calls'] and not node['terminal']):
                candidates+=1
    reason=None
    if not candidates:reason='no_unprotected_advisory_candidates'
    elif total+opaque>MAX_ADVISORY_LABELS:reason='advisory_output_budget_exceeded'
    return dict(request_model=reason is None,reason=reason,total_nodes=total,
                opaque_contexts=opaque,candidate_nodes=candidates,max_labels=MAX_ADVISORY_LABELS)


def retained_without_request(plan):
    if plan['request_model']:raise ValueError('Local retention needs a non-requestable advisory plan')
    return dict(status='not_executed_optional_relevance_full_context_retained',labels=[],context_labels=[],
                preflight=plan,full_context_preserved=True,semantic_correctness_proven=False,
                scope='optional advisory labels not requested; review original full context; no source removed',
                models_called=0)


def validate_relevance(result, views):
    known={}
    protected=set()
    empty_symbols=set()
    for entry in views:
        view=entry['view'];symbol=entry['symbol_id']
        nodes=view.get('graph',{}).get('nodes',[])
        if not nodes:empty_symbols.add(symbol)
        for node in nodes:
            key=(symbol,node['id']);known[key]=node
            if (view.get('status')!='bounded_dependency_view_not_sound_slice'
                    or node['id'] in view.get('selected_nodes',[]) or node['calls'] or node['terminal']):
                protected.add(key)
    if not isinstance(result,dict):raise ValueError('Relevance result must be an object')
    labels=result.get('labels')
    if not isinstance(labels,list):raise ValueError('Relevance labels required')
    extra_context=result.get('context_labels',[])
    if not isinstance(extra_context,list):raise ValueError('Context labels must be an array')
    seen=set();seen_context=set();node_labels=[];context_labels=[]
    for item in labels+extra_context:
        if not isinstance(item,dict):raise ValueError('Relevance label must be an object')
        symbol=item.get('symbol_id');node=item.get('node_id')
        if not isinstance(symbol,str):raise ValueError('Malformed symbol identity')
        if item.get('relevance') not in ['relevant','irrelevant_candidate','unknown']:
            raise ValueError('Unknown relevance classification')
        if not isinstance(item.get('reason'),str) or not item['reason'].strip() or not item.get('evidence'):
            raise ValueError('Relevance label requires explanation and source evidence')
        if node is None:
            if symbol not in empty_symbols or symbol in seen_context:raise ValueError('Null node only allowed once for a known context with no AST nodes')
            if item['relevance']=='irrelevant_candidate':raise ValueError('Opaque or unsupported context cannot be excluded')
            seen_context.add(symbol);context_labels.append(item);continue
        if type(node) is not int:raise ValueError('Malformed node identity')
        key=(symbol,node)
        if key not in known or key in seen:raise ValueError('Unknown/duplicate relevance label')
        seen.add(key);node_labels.append(item)
        if item['relevance']=='irrelevant_candidate' and key in protected:
            raise ValueError('Cannot omit a dependence node, opaque call, control dependency or terminal effect')
    if seen!=set(known):raise ValueError('Every indexed node needs a label; no silent omissions')
    return dict(status='model_relevance_judgment_unverified',labels=node_labels,context_labels=context_labels,
                unlabelled_context_symbols=sorted(empty_symbols-seen_context),
                full_context_preserved=True,semantic_correctness_proven=False,
                scope='advisory review focus only; not executable or sound semantic pruning')


def retained_context_fallback(reason):
    """No semantic label survives failed local validation; full source stays."""
    return dict(status='unusable_relevance_full_context_retained',labels=[],context_labels=[],
                validation_error=str(reason),full_context_preserved=True,semantic_correctness_proven=False,
                scope='optional relevance judgment unavailable; review original full source; no retry')
