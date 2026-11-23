"""Auditable extraction DTO normalization; no change to normative meaning."""
from copy import deepcopy

LIST_FIELDS=['req_fields','res_fields','preconditions','exceptions']


def normalize(value,document):
    result=deepcopy(value);changes=[];anchors=[]
    lines={l['line']:l['text'] for l in document['lines']}
    if not isinstance(result.get('rules'),list):return result
    for index,atom in enumerate(result['rules'],1):
        if not isinstance(atom,dict):continue
        unknown=list(atom.get('unspecified_list_fields',[]))
        for field in LIST_FIELDS:
            if field not in atom or isinstance(atom[field],list):continue
            original=atom[field]
            if isinstance(original,str) and original.strip():atom[field]=[original]
            elif original is None or original=='':
                atom[field]=[]
                if field not in unknown:unknown.append(field)
            else:continue
            changes.append(dict(rule_index=index,field=field,original_value=original,
                interpretation='verbatim scalar retained as one entry' if isinstance(original,str) and original.strip()
                               else 'unspecified, not evidence that no condition or exception exists'))
        if unknown:atom['unspecified_list_fields']=unknown
        evidence=atom.get('evidence')
        if isinstance(evidence,list):
            for n,e in enumerate(evidence):
                # Only the NEW line-reference DTO is materialized. Old full
                # quotes are never overwritten to make failed evidence pass.
                if isinstance(e,dict) and set(e)=={'line'} and type(e['line']) is int and e['line'] in lines:
                    evidence[n]=dict(file=document['file'],line=e['line'],quote=lines[e['line']])
                    anchors.append(dict(rule_index=index,line=e['line']))
    if changes:result['local_list_normalizations']=changes
    if anchors:result['local_source_anchor_materialization']=dict(source=document['file'],anchors=anchors,
        semantic_entailment_verified=False,method='model selected supplied line IDs; exact text attached from fixed source')
    return result
