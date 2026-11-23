"""Lossless columnar encoding of repeated source/field metadata for text judges."""
from copy import deepcopy


def table(records):
    if not records:return records
    if not all(isinstance(r,dict) and set(r)==set(records[0]) for r in records):return records
    columns=list(records[0])
    return dict(encoding='protocolguard_lossless_table_v1',columns=columns,
                rows=[[r[c] for c in columns] for r in records])


def records(value):
    if isinstance(value,dict) and value.get('encoding')=='protocolguard_lossless_table_v1':
        return [dict(zip(value['columns'],row)) for row in value['rows']]
    return value


def grouped_fields(fields):
    if not fields or not all(isinstance(r,dict) and isinstance(r.get('file'),str)
                            and isinstance(r.get('classification'),str) and set(r)==set(fields[0]) for r in fields):
        return table(fields)
    columns=[k for k in fields[0] if k not in ['file','classification']];groups={}
    for i,r in enumerate(fields):
        key=(r['file'],r['classification'])
        group=groups.setdefault(key,dict(file=key[0],classification=key[1],columns=columns,original_indices=[],rows=[]))
        group['original_indices'].append(i);group['rows'].append([r[k] for k in columns])
    return dict(encoding='protocolguard_lossless_grouped_fields_v1',
                semantics='shared file/classification applies to each row; original_indices preserves record order',groups=list(groups.values()))


def ungroup_fields(value):
    if not isinstance(value,dict) or value.get('encoding')!='protocolguard_lossless_grouped_fields_v1':return records(value)
    restored=[]
    for g in value['groups']:
        for i,row in zip(g['original_indices'],g['rows']):
            restored.append((i,dict(file=g['file'],classification=g['classification'],**dict(zip(g['columns'],row)))))
    return [r for i,r in sorted(restored)]


def pack_context(value):
    if not isinstance(value,dict) or not isinstance(value.get('slice'),dict):return value
    result=deepcopy(value);slice=result['slice']
    fields=slice.get('field_evidence')
    if isinstance(fields,list):slice['field_evidence']=grouped_fields(fields)
    for doc in slice.get('code',[]):
        if isinstance(doc.get('lines'),list):doc['lines']=table(doc['lines'])
    for doc in result.get('norms',[]):
        if isinstance(doc.get('lines'),list):doc['lines']=table(doc['lines'])
    return result


def unpack_context(value):
    result=deepcopy(value)
    if not isinstance(result,dict) or not isinstance(result.get('slice'),dict):return result
    slice=result['slice']
    if 'field_evidence' in slice:slice['field_evidence']=ungroup_fields(slice['field_evidence'])
    for doc in slice.get('code',[]):doc['lines']=records(doc['lines'])
    for doc in result.get('norms',[]):doc['lines']=records(doc['lines'])
    return result
