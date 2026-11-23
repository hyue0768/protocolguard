"""Execute a supplied minimal module set in a fresh process, with network disabled."""
import ast
import base64
import copy
import importlib
import json
import socket
import sys
import types
from pathlib import Path
sys.dont_write_bytecode=True

def run(data):
    def denied(*a,**kw):raise RuntimeError('Network disabled in release probe')
    socket.socket=denied;socket.create_connection=denied
    source=data['files'];ns={};out=[]
    if 'base' in source and 'payments' in source:
        for name in ['x402','x402.schemas']:
            m=types.ModuleType(name);m.__path__=[];sys.modules[name]=m
        for key in ['base','payments']:
            name='x402.schemas.'+key;m=types.ModuleType(name);m.__package__='x402.schemas';sys.modules[name]=m
            exec(compile(source[key],data['paths'][key],'exec'),m.__dict__)
            ns[key]=m
        P=ns['payments'].PaymentRequired
        seed=data['seed']
        def observe(name,obj):
            try:
                result=P.model_validate(obj)
                out.append({'name':name,'behavior':'accepted','decoded_version':getattr(result,'x402_version',None)})
            except Exception as e:out.append({'name':name,'behavior':'rejected','error':type(e).__name__})
        if seed:
            observe('coeval_spec_example',seed)
            for c in data['corpus']:observe(c['name'],c['value'])
        else:out.append({'name':'schema_example','behavior':'not_run_no_coeval_seed'})
    if 'encoding' in source:
        # Only top-level base64 helpers, rather than importing the SDK entrypoint.
        tree=ast.parse(source['encoding'])
        nodes=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom)) and
               ((isinstance(n,ast.Import) and all(a.name in ('base64','typing') for a in n.names)) or
                (isinstance(n,ast.ImportFrom) and n.module in ('typing','__future__')))]
        nodes += [n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name in ('safe_base64_encode','safe_base64_decode')]
        space={};exec(compile(ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[])),data['paths']['encoding'],'exec'),space)
        if 'safe_base64_encode' in space and 'safe_base64_decode' in space:
            for s in ['hello','支付 x402 € 🚀','', 'a'*1024]:
                try:
                    value=space['safe_base64_decode'](space['safe_base64_encode'](s))
                    out.append({'name':'base64_roundtrip_'+str(len(s)),'behavior':'returned','value':value==s})
                except Exception as e:out.append({'name':'base64_roundtrip_'+str(len(s)),'behavior':'threw','error':type(e).__name__})
    return {'results':out,'scope':'component execution; no outer SDK entrypoint, transport or blockchain'}
if __name__=='__main__':
    try:print(json.dumps(run(json.load(sys.stdin))))
    except Exception as e:print(json.dumps({'harness_error':type(e).__name__+': '+str(e)}))
