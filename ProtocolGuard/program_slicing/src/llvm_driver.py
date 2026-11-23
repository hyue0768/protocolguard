"""Offline cached-decision bridge: config.toml -> LLVM pass -> complete source -> SQLite."""
import argparse
import importlib.util
import json
import os
import sqlite3
import subprocess
import tomllib
from pathlib import Path


def run(config_path, decisions_path, output):
    cfg=tomllib.loads(config_path.read_text()); project=cfg['project']
    rules=json.loads(Path(project['rule_path']).read_text())
    decisions=json.loads(decisions_path.read_text());output.mkdir(parents=True,exist_ok=True)
    plugin=Path(__file__).resolve().parents[1]/'build/src/libMatchPass.so'
    module=project['original_llvm_ir_path']
    db_path=output/'slices.db'
    reports=[]
    with sqlite3.connect(db_path) as db:
        db.execute('CREATE TABLE IF NOT EXISTS rule_code_snippet (rule_desc TEXT PRIMARY KEY, code_snippet TEXT, call_graph TEXT, llm_response TEXT)')
        for n,rule in enumerate(rules):
            key=rule.get('id',str(n)); decision=decisions.get(key)
            if decision is None:
                reports.append({'id':key,'status':'pending_decision'});continue
            criteria=output/f'{n}.criteria.json';criteria.write_text(json.dumps(decision))
            result=output/f'{n}.slice.json';env=os.environ.copy()
            env.update(PG_CRITERIA=str(criteria.resolve()),PG_OUTPUT=str(result.resolve()))
            subprocess.run(['opt-18','-load-pass-plugin',str(plugin),'-passes=match-pass',module,'-disable-output'],env=env,check=True)
            data=json.loads(result.read_text());locations={}
            for inst in data['instructions']:
                if 'file' in inst and 'line' in inst:locations.setdefault(inst['file'],set()).add(inst['line'])
            # Semantic decisions are supplied externally; never prune critical
            # intermediaries. Only explicitly excluded leaves can be removed.
            excluded=set(decision.get('exclude_functions', []))
            outgoing={edge['caller'] for edge in data['calls'] if edge['callee']!='<indirect-unresolved>'}
            if excluded & outgoing:
                raise ValueError('Refusing to prune a non-leaf call-graph intermediary')
            fragments=[]
            # Conservative completion retains every enclosing function from clang AST.
            astspec=importlib.util.spec_from_file_location('ast_export',Path(__file__).with_name('ast_export.py'))
            astmod=importlib.util.module_from_spec(astspec);astspec.loader.exec_module(astmod)
            for file, lines in locations.items():
                path=Path(file)
                if not path.is_file():raise ValueError(f'Source unavailable: {path}')
                astfile=astmod.export(path,decision.get('clang_flags',[]))
                ranges=json.loads(astfile.read_text())['functions'];text=path.read_text().splitlines()
                for f in ranges:
                    a,b=f['overall']['start'],f['overall']['end']
                    if f['name'] not in excluded and any(a<=line<=b for line in lines):fragments.append(f'// {file}:{a}-{b}\n'+'\n'.join(text[a-1:b]))
            db.execute('INSERT INTO rule_code_snippet VALUES (?,?,?,NULL) ON CONFLICT(rule_desc) DO UPDATE SET code_snippet=excluded.code_snippet,call_graph=excluded.call_graph,llm_response=NULL',
                       (rule['rule'],'\n\n'.join(fragments),json.dumps(data['calls'])))
            reports.append({'id':key,'status':'llvm_slice_with_full_function_completion','semantic_analysis':'not_run'})
    (output/'report.json').write_text(json.dumps(reports,indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--decisions',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();run(a.config.resolve(),a.decisions.resolve(),a.output.resolve())
