"""Pinned x402 Markdown input -> candidates -> compatible rules -> source/DB context.
Only standard-library code; no credentials, model calls or network operations.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract(path, relative):
    heading, fenced, result = [], False, []
    for line_no, text in enumerate(path.read_text().splitlines(), 1):
        if text.lstrip().startswith('```'):
            fenced = not fenced
            continue
        if fenced:
            continue
        m = re.match(r'^(#{1,6})\s+(.+)', text)
        if m:
            level = len(m[1]); heading = heading[:level-1] + [m[2]]
            continue
        if re.search(r'\b(MUST(?: NOT)?|SHOULD(?: NOT)?|REQUIRED|must|should|required|shall)\b', text):
            result.append(dict(id=hashlib.sha256(f'{relative}:{line_no}:{text}'.encode()).hexdigest()[:16],
                               source=relative, line=line_no, heading=heading[:], text=text.strip(),
                               status='candidate_unreviewed'))
    return result


def run(profile):
    cfg=json.loads(profile.read_text()); upstream=(profile.parent/cfg['upstream']).resolve()
    if (upstream/'.git').exists():
        head=subprocess.check_output(['git','-C',str(upstream),'rev-parse','HEAD'],text=True).strip()
        if subprocess.check_output(['git','-C',str(upstream),'status','--porcelain'],text=True).strip():
            raise ValueError('Upstream checkout modified; refusing unpinned inputs')
    else:
        lock=json.loads((upstream/'UPSTREAM_PROVENANCE.json').read_text())
        head=lock['commit']
        tree=json.loads((BASE/cfg.get('tree','upstream-tree.json')).read_text())
        if tree.get('truncated') or tree['sha'] != cfg['commit']:
            raise ValueError('Incomplete or wrong upstream Git tree')
        for item in tree['tree']:
            if item['type']!='blob': continue
            path=upstream/item['path']
            data=str(path.readlink()).encode() if path.is_symlink() else path.read_bytes()
            blob=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
            if blob!=item['sha']:raise ValueError(f"Modified upstream file: {item['path']}")
    if head != cfg['commit']:
        raise ValueError(f'Upstream HEAD mismatch: {head}')
    out=(profile.parent/cfg['output']).resolve();out.mkdir(parents=True,exist_ok=True)
    candidates, manifest=[],[]
    for name in cfg['specs']:
        src=upstream/name;dest=out/'specs'/Path(name).relative_to('specs')
        dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dest)
        manifest.append(dict(path=name,sha256=digest(src)))
        candidates.extend(extract(src,name))
    all_specs=[str(p.relative_to(upstream)) for p in sorted((upstream/'specs').rglob('*.md'))]
    (out/'manifest.json').write_text(json.dumps(dict(commit=head,protocol_version=2,imported=manifest,
        not_imported=[p for p in all_specs if p not in cfg['specs']],
        limitation='Candidate matching is not complete normative rule extraction.'),indent=2))
    (out/'candidates.json').write_text(json.dumps(candidates,indent=2))
    rules=json.loads((BASE/'rules.json').read_text())
    for r in rules:
        src=upstream/r['source'];lines=src.read_text().splitlines()
        if r['evidence'] not in '\n'.join(lines):
            raise ValueError(f"Rule evidence missing: {r['id']}")
        r['source_line']=next(i+1 for i,t in enumerate(lines) if r['evidence'] in t)
    (out/'processed_results.json').write_text(json.dumps(rules,indent=2))
    spec=importlib.util.spec_from_file_location('source_slicer',BASE.parent/'program_slicing/src/source_slicer.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    report=mod.slice_python(upstream/'python/x402',rules,json.loads((BASE/'decisions.json').read_text()),out/'sqlite_x402.db')
    (out/'slicing.json').write_text(json.dumps(report,indent=2))
    prompts=out/'review_prompts';prompts.mkdir(exist_ok=True)
    with sqlite3.connect(out/'sqlite_x402.db') as db:
        for n,(rule,code,graph) in enumerate(db.execute('SELECT rule_desc,code_snippet,call_graph FROM rule_code_snippet ORDER BY rule_desc')):
            (prompts/f'{n:03d}.txt').write_text(
                'Offline review input. No model has evaluated this candidate.\n'
                'Assess the rule in its source context; report uncertainty and missing callers.\n'
                'Do not infer end-to-end exploitability from schema acceptance.\n'
                f'Rule: {rule}\nCall graph: {graph}\nSource context:\n{code}\n')
    print(json.dumps(dict(commit=head,documents=len(manifest),candidates=len(candidates),rules=len(rules),slices=len(report))))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--profile',type=Path,default=BASE/'profile.json');a=p.parse_args();run(a.profile.resolve())
