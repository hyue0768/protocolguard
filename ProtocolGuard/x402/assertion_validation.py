"""Separate non-executable observations from actual bounded assertions."""
from copy import deepcopy


def validate(value,rule_id,docs,choices):
    import version_audit as a
    known={c['id'] for c in choices}
    value=deepcopy(value)
    status=value.get('adapter_status')
    if isinstance(status,dict):
        # Accept only an explicit absence report. Never infer support from a
        # malformed status object, discard suggestions, or execute them.
        missing=status.get('adapter_missing')
        observations=value.get('assertions')
        if (set(status)=={'supported_component_cases','adapter_missing'}
                and status['supported_component_cases']==[] and isinstance(missing,list) and missing
                and all(isinstance(x,str) and x in known for x in missing)
                and isinstance(observations,list)
                and all(isinstance(x,dict) and x.get('predicate')=='observe_only' for x in observations)):
            value['original_adapter_status']=deepcopy(status)
            value['adapter_status']='adapter_missing'
            value['local_status_interpretation']='explicit empty supported-case list retained as missing adapter; no capability inferred'
    if (value.get('rule_id')!=rule_id or value.get('adapter_status') not in ['supported_component_cases','adapter_missing']
            or not isinstance(value.get('assertions'),list) or a.grounding(value,docs)):
        raise ValueError('Assertion schema/evidence failed; inspect saved response')
    for item in value['assertions']:
        if (not isinstance(item,dict) or item.get('case_id') not in known
                or item.get('predicate') not in ['rejected','roundtrip_equal','observe_only'] or not item.get('evidence')):
            raise ValueError('Unsupported assertion/case; no generated code execution')
    result=deepcopy(value)
    if result['adapter_status']=='adapter_missing' and result['assertions']:
        if any(x['predicate']!='observe_only' for x in result['assertions']):
            raise ValueError('Missing adapter cannot have executable assertions')
        result['non_executable_observations']=result['assertions'];result['assertions']=[]
        result['local_plan_interpretation']='observe_only suggestions retained without execution; adapter remains missing; no rule validated'
    return result
