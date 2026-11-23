"""Manual native LLVM18 prepare/replay with distance and assertion observations.

Consumes existing corpus files only. Does not synthesize protocol messages, run
transactions, or claim reproduction of the original SelectFuzz/AFLNet pipeline.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import random

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2)+'\n')


def environment(extra=None):
    return dict(PATH=os.environ.get('PATH','/usr/bin:/bin'), LC_ALL='C', **(extra or {}))


def prepare(source, criteria, output):
    source, criteria, output = source.resolve(), criteria.resolve(), output.resolve()
    if output.exists():
        raise ValueError('Output exists; no overwrite')
    for executable in ['clang-18', 'opt-18']:
        if not shutil.which(executable):
            raise ValueError('Missing tool: '+executable)
    plugin = HERE/'build18/libDirected18.so'
    if not plugin.is_file():
        raise ValueError('Build the LLVM18 plugin with build_directed18.sh first')
    decision = json.loads(criteria.read_text())
    if not isinstance(decision.get('function'),str) or not decision['function']:
        raise ValueError('criteria.function required')
    if 'line' in decision and (type(decision['line']) is not int or decision['line'] < 1):
        raise ValueError('criteria.line must be positive')
    output.mkdir(parents=True)
    (output/'criteria.json').write_text(criteria.read_text())
    commands = [
        ['clang-18','-g','-O0','-Xclang','-disable-O0-optnone','-emit-llvm','-c',str(source),'-o',str(output/'original.bc')],
        ['opt-18','-load-pass-plugin',str(plugin),'-passes=function(mem2reg),pg-directed',str(output/'original.bc'),'-o',str(output/'instrumented.bc')],
        ['clang-18',str(output/'instrumented.bc'),str(HERE/'trace_runtime.c'),'-o',str(output/'target')],
    ]
    env = environment(dict(PG_DIRECTED_CRITERIA=str(output/'criteria.json'), PG_DIRECTED_GRAPH=str(output/'graph.json')))
    logs = []
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, env=env)
        logs.append(dict(command=command, returncode=result.returncode, stderr=result.stderr[:12000]))
        save(output/'build.json',logs)
        if result.returncode:
            raise ValueError('Build failed; diagnostics retained, no retry')
    artifacts = ['original.bc','instrumented.bc','target','graph.json','criteria.json']
    manifest = dict(source=str(source),source_sha256=digest(source),plugin_sha256=digest(plugin),
                    runtime_sha256=digest(HERE/'trace_runtime.c'),
                    artifacts={name:digest(output/name) for name in artifacts},
                    target_execution='not_run',method='LLVM18 CFG with direct and type-compatible indirect candidates; not original DFUZZ')
    save(output/'manifest.json',manifest)
    return manifest


def replay(prepared, corpus, output, execute=False, timeout=3, max_cases=100):
    if not execute:
        raise ValueError('Target execution requires --execute')
    prepared, corpus, output = prepared.resolve(), corpus.resolve(), output.resolve()
    if output.exists():
        raise ValueError('Replay output exists; no overwrite')
    manifest = json.loads((prepared/'manifest.json').read_text())
    for name, value in manifest['artifacts'].items():
        if name not in ['original.bc','instrumented.bc','target','graph.json','criteria.json'] or digest(prepared/name)!=value:
            raise ValueError('Prepared artifact identity mismatch')
    if not 1 <= max_cases <= 10000 or not 0 < timeout <= 60:
        raise ValueError('Invalid execution bounds')
    seeds = sorted(p for p in corpus.iterdir() if p.is_file() and not p.is_symlink())
    if not seeds:
        raise ValueError('No existing corpus files')
    if len(seeds)>max_cases:
        raise ValueError('Corpus exceeds max-cases; no silent truncation')
    if any(p.stat().st_size > 1048576 for p in seeds):
        raise ValueError('Seed exceeds 1 MiB input bound')
    output.mkdir(parents=True)
    results, covered = [], set()
    for index, seed in enumerate(seeds):
        raw = seed.read_bytes();trace=output/(str(index)+'.trace')
        env=environment(dict(PG_DIRECTED_TRACE=str(trace)))
        try:
            run=subprocess.run([str(prepared/'target')],input=raw,capture_output=True,env=env,timeout=timeout)
            returncode=run.returncode;status='completed' if returncode==0 else 'nonzero_exit_observation'
        except subprocess.TimeoutExpired:
            returncode=None;status='timeout_observation'
        pairs=[]
        if trace.exists():
            for line in trace.read_text().splitlines():
                block, distance = map(int,line.split());pairs.append((block,distance))
        visits={p[0] for p in pairs};distances=[p[1] for p in pairs if p[1]>=0]
        results.append(dict(seed=seed.name,seed_sha256=hashlib.sha256(raw).hexdigest(),status=status,
                            returncode=returncode,min_distance=min(distances) if distances else None,
                            target_reached=0 in distances,new_blocks=sorted(visits-covered),trace=str(trace),
                            interpretation='execution observation; no vulnerability or safety conclusion'))
        covered.update(visits)
    # A reproducible priority list for further manual corpus selection, not an
    # automatic claim of generated inputs or an AFL-compatible feedback loop.
    priority=sorted(results,key=lambda r:(r['min_distance'] is None,r['min_distance'] or 0,-len(r['new_blocks']),r['seed']))
    result=dict(status='bounded_native_corpus_replay_completed',results=results,
                priority=[r['seed'] for r in priority],covered_blocks=sorted(covered),
                generated_inputs=0,chain_activity='not_observed_by_native_adapter',formal_proof=False)
    save(output/'results.json',result)
    return result


def fuzz(prepared,corpus,output,execute=False,generate_inputs=False,timeout=3,max_cases=100,seed=1):
    """Bounded byte mutation for native stdin targets, only on explicit opt-in.

    No protocol packet synthesis, Scapy, AFL shared memory, symbolic execution,
    or SelectFuzz equivalence is implied by this distance-guided adaptation.
    """
    if not execute or not generate_inputs:
        raise ValueError('Fuzzing requires both --execute and --generate-inputs')
    if not shutil.which('bwrap'):raise ValueError('Network namespace sandbox missing')
    if not 1<=max_cases<=10000 or not 0<timeout<=60:raise ValueError('Invalid fuzz bounds')
    prepared,corpus,output=prepared.resolve(),corpus.resolve(),output.resolve()
    if output.exists():raise ValueError('Fuzz output exists; no overwrite')
    manifest=json.loads((prepared/'manifest.json').read_text())
    for name,value in manifest['artifacts'].items():
        if name not in ['original.bc','instrumented.bc','target','graph.json','criteria.json'] or digest(prepared/name)!=value:
            raise ValueError('Prepared artifact identity mismatch')
    files=sorted(p for p in corpus.iterdir() if p.is_file() and not p.is_symlink())
    if not files or len(files)>max_cases:raise ValueError('Existing corpus must fit nonempty case budget')
    if any(p.stat().st_size>1048576 for p in files):raise ValueError('Seed exceeds 1 MiB')
    queue=[(p.read_bytes(),None) for p in files]
    output.mkdir(parents=True);(output/'inputs').mkdir()
    rng=random.Random(seed);seen=set();covered=set();results=[];attempts=0;best=None
    while queue and len(results)<max_cases and attempts<max_cases*20:
        attempts+=1;raw,parent=queue.pop(0);identity=hashlib.sha256(raw).hexdigest()
        if identity in seen:continue
        seen.add(identity);index=len(results);input_file=output/'inputs'/(str(index)+'.bin');input_file.write_bytes(raw)
        trace=output/(str(index)+'.trace')
        command=['bwrap','--unshare-all','--die-with-parent','--new-session',
                 '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin','--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
                 '--proc','/proc','--dev','/dev','--tmpfs','/tmp',
                 '--ro-bind',str(prepared),'/target','--bind',str(output),'/out',
                 '--chdir','/out','--clearenv','--setenv','PG_DIRECTED_TRACE','/out/'+trace.name,'--','/target/target']
        # Output is discarded: source-level findings must use separately saved
        # assertions/traces, not arbitrary target stdout or inherited secrets.
        try:
            run=subprocess.run(command,input=raw,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                               env=environment(),timeout=timeout)
            status='completed' if run.returncode==0 else 'nonzero_exit_observation';returncode=run.returncode
        except subprocess.TimeoutExpired:status='timeout_observation';returncode=None
        pairs=[tuple(map(int,line.split())) for line in trace.read_text().splitlines()] if trace.exists() else []
        visits={p[0] for p in pairs};distances=[p[1] for p in pairs if p[1]>=0]
        distance=min(distances) if distances else None;new=visits-covered;covered.update(visits)
        improved=distance is not None and (best is None or distance<best)
        if improved:best=distance
        results.append(dict(input=str(input_file),sha256=identity,parent=parent,status=status,returncode=returncode,
                            min_distance=distance,new_blocks=sorted(new),target_reached=0 in distances,
                            interpretation='bounded execution observation; not confirmed vulnerability'))
        generated=[]
        for _ in range(4):
            mutant=bytearray(raw)
            if not mutant:mutant.append(rng.randrange(256))
            else:
                position=rng.randrange(len(mutant));mutant[position]^=1<<rng.randrange(8)
            if len(mutant)<1048576 and rng.randrange(4)==0:mutant.append(rng.randrange(256))
            generated.append((bytes(mutant),index))
        # New coverage or reduced graph distance receives priority. Keep the
        # scheduler bounded independently of the target's behavior.
        queue=(generated+queue if improved or new else queue+generated)[:max_cases*4]
    result=dict(status='bounded_distance_guided_native_fuzzing',results=results,
                random_seed=seed,case_budget=max_cases,attempts=attempts,best_distance=best,
                covered_blocks=sorted(covered),queue_policy='distance improvement or new block coverage first; bounded queue',
                generated_inputs=sum(r['parent'] is not None for r in results),
                external_network='disabled by required namespace sandbox',formal_proof=False,
                whole_protocol_compliance='unknown',original_dfuzz_reproduction=False)
    save(output/'results.json',result);return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='stage',required=True)
    p=sub.add_parser('prepare');p.add_argument('--source',type=Path,required=True);p.add_argument('--criteria',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('replay');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--corpus',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--execute',action='store_true');p.add_argument('--timeout',type=float,default=3);p.add_argument('--max-cases',type=int,default=100)
    p=sub.add_parser('fuzz');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--corpus',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--execute',action='store_true');p.add_argument('--generate-inputs',action='store_true');p.add_argument('--timeout',type=float,default=3);p.add_argument('--max-cases',type=int,default=100);p.add_argument('--seed',type=int,default=1)
    args=vars(parser.parse_args());stage=args.pop('stage')
    result=dict(prepare=prepare,replay=replay,fuzz=fuzz)[stage](**args)
    print(json.dumps(dict(output=str(args['output']),status=result.get('status','prepared_not_executed'))))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.TimeoutExpired) as error:
        raise SystemExit('Stopped: '+str(error))
