"""Execute pinned upstream schema/header functions without loading optional SDK adapters.
Observations are component behavior, not end-to-end vulnerability verdicts.
"""
import argparse
import base64
import copy
import importlib
import json
import re
import sys
import types
from pathlib import Path

sys.dont_write_bytecode = True
BASE=Path(__file__).resolve().parent


def load_sdk(root):
    # Private namespace avoids top-level SDK imports and optional blockchain dependencies.
    for name,path in [('pg_sdk',root),('pg_sdk.schemas',root/'schemas'),('pg_sdk.http',root/'http')]:
        package=types.ModuleType(name);package.__path__=[str(path)];sys.modules[name]=package
    payments=importlib.import_module('pg_sdk.schemas.payments')
    responses=importlib.import_module('pg_sdk.schemas.responses')
    schema=sys.modules['pg_sdk.schemas']
    for name in ['PaymentPayload','PaymentRequired']:
        setattr(schema,name,getattr(payments,name))
    schema.SettleResponse=responses.SettleResponse
    http=importlib.import_module('pg_sdk.http.utils')
    return payments,http


def run(upstream):
    from pydantic import ValidationError
    payments,http=load_sdk(upstream/'python/x402')
    core=(upstream/'specs/x402-specification-v2.md').read_text()
    examples=[]
    for block in re.findall(r'```json\s*\n(.*?)```',core,re.S):
        try: examples.append(json.loads(block))
        except json.JSONDecodeError: pass  # Other spec examples contain placeholders/comments.
    required=next(x for x in examples if isinstance(x,dict) and 'accepts' in x and 'resource' in x)
    model=payments.PaymentRequired.model_validate(required)
    header=http.encode_payment_required_header(model)
    decoded=http.decode_payment_required_header(header)
    assert decoded.model_dump()==model.model_dump()
    assert json.loads(base64.b64decode(header))['x402Version']==2
    outcomes=[{'case':'official_PaymentRequired_example_and_header_roundtrip','result':'pass'}]
    bad=copy.deepcopy(required);bad['accepts'][0]['network']='base-mainnet'
    try:
        payments.PaymentRequired.model_validate(bad)
    except ValidationError:
        outcomes.append({'case':'reject_non_CAIP2_network','result':'pass'})
    else:
        raise AssertionError('Non CAIP2 network accepted')
    for label,mutate in [('version_99',lambda x:x.update(x402Version=99)),
                         ('missing_resource',lambda x:x.pop('resource'))]:
        data=copy.deepcopy(required);mutate(data)
        wire=base64.b64encode(json.dumps(data).encode()).decode()
        try:
            value=http.decode_payment_required_header(wire)
            outcomes.append({'case':label,'result':'accepted_by_schema_and_header_decoder',
                             'scope':'component observation; outer validation/context not evaluated',
                             'decoded_version':value.x402_version})
        except (ValidationError,ValueError):
            outcomes.append({'case':label,'result':'rejected'})
    return outcomes

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--upstream',type=Path,default=BASE.parent.parent/'x402_upstream_20261113_2178d4b_snapshot');p.add_argument('--output',type=Path,default=BASE/'output/sdk-observations.json')
    a=p.parse_args();out=run(a.upstream.resolve());a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(out,indent=2));print(json.dumps(out,indent=2))
