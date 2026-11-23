"""Manual, network-isolated native project regression adapters.

These execute coeval repository tests, not automatically spec-derived payment
oracles. Requires an explicit commit, project subdirectory and local Git store.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile

CONFIG={
    'go':dict(tool='go',manifest='go.mod',command=['go','test','-json','-mod=readonly','./...'],
              env=dict(GOPROXY='off',GOSUMDB='off',GOTOOLCHAIN='local',GOCACHE='/out/cache/go',GOPATH='/deps',GOMODCACHE='/deps/pkg/mod')),
    'rust':dict(tool='cargo',manifest='Cargo.toml',command=['cargo','test','--offline','--locked','--message-format=json'],
                env=dict(CARGO_HOME='/deps',CARGO_TARGET_DIR='/out/cache/rust',CARGO_NET_OFFLINE='true')),
    'solidity':dict(tool='forge',manifest='foundry.toml',command=['forge','test','--offline','--json'],
                    env=dict(FOUNDRY_OUT='/out/cache/forge-out',FOUNDRY_CACHE_PATH='/out/cache/forge-cache',SVM_HOME='/deps')),
    'java':dict(tool='mvn',manifest='pom.xml',command=['mvn','--offline','-B','-Dmaven.repo.local=/deps','test'],env={}),
}


def plan(language,subdir):
    if language not in CONFIG:raise ValueError('Unknown native language')
    if not isinstance(subdir,str) or not subdir:raise ValueError('Explicit project subdirectory required')
    path=PurePosixPath(subdir)
    if path.is_absolute() or '..' in path.parts:raise ValueError('Relative project subdirectory required')
    config=CONFIG[language]
    return dict(language=language,subdir=str(path),manifest=config['manifest'],command=config['command'],
                tool=shutil.which(config['tool']),sandbox=shutil.which('bwrap'),env=config['env'],
                evidence_kind='coeval project regression tests; no automatic security-goal mapping',
                rules_covered=[],semantic_correctness_proven=False)


def sandbox_command(work,output,dependency_cache,subdir,command,extra_env=None):
    if work.resolve()!=(output/'work').resolve():raise ValueError('Sandbox work must be the disposable output/work copy')
    args=['bwrap','--unshare-all','--die-with-parent','--new-session',
          '--ro-bind','/usr','/usr','--symlink','usr/bin','/bin',
          '--symlink','usr/lib','/lib','--symlink','usr/lib64','/lib64',
          '--proc','/proc','--dev','/dev','--tmpfs','/tmp',
          '--bind',str(output),'/out','--clearenv',
          '--setenv','PATH','/usr/local/bin:/usr/bin:/bin',
          '--setenv','LC_ALL','C','--setenv','TMPDIR','/tmp']
    if dependency_cache:
        args+=['--ro-bind',str(dependency_cache),'/deps']
    else:args+=['--dir','/deps']
    # Build tools may write generated files in this disposable source copy.
    args+=['--chdir','/out/work/'+subdir]
    for key,value in (extra_env or {}).items():args+=['--setenv',key,value]
    args+=['--',*command]
    return args


def execute(store,commit,language,subdir,output,allow_execute=False,dependency_cache=None,timeout=300):
    if not allow_execute:raise ValueError('Native target tests require --execute')
    if len(commit)!=40 or any(c not in '0123456789abcdef' for c in commit):raise ValueError('Pinned Git commit required')
    config=plan(language,subdir)
    if not config['tool'] or not config['sandbox']:raise ValueError('Native toolchain or network sandbox missing; no execution')
    if not config['tool'].startswith('/usr/'):raise ValueError('Toolchain must reside under mounted /usr')
    if not 0 < timeout <= 3600:raise ValueError('Invalid timeout bound')
    output=output.resolve();store=store.resolve()
    if output.exists():raise ValueError('Native output exists; no overwrite')
    if dependency_cache:
        dependency_cache=dependency_cache.resolve()
        if not dependency_cache.is_dir():raise ValueError('Dependency cache must be an explicit directory')
    output.mkdir(parents=True)
    env=dict(PATH=os.environ.get('PATH','/usr/bin:/bin'),LC_ALL='C',GIT_NO_LAZY_FETCH='1',GIT_CONFIG_NOSYSTEM='1')
    archive=output/'source.tar'
    with archive.open('wb') as stream:
        result=subprocess.run(['git','-C',str(store),'archive','--format=tar',commit],stdout=stream,
                              stderr=subprocess.PIPE,timeout=120,env=env)
    if result.returncode:raise ValueError('Local pinned Git archive unavailable; no fetch or retry')
    work=output/'work';work.mkdir()
    with tarfile.open(archive) as bundle:
        for entry in bundle.getmembers():
            # Never follow symlinks, import untracked files, or copy .git credentials.
            if entry.issym() or entry.islnk():raise ValueError('Archive links require explicit separate materialization')
            if not entry.isfile() and not entry.isdir():raise ValueError('Unsupported archive entry')
        bundle.extractall(work,filter='data')
    if not (work/subdir/config['manifest']).is_file():raise ValueError('Selected native project manifest absent in pinned release')
    config['command']=[config['tool'],*config['command'][1:]]
    command=sandbox_command(work,output,dependency_cache,subdir,config['command'],config['env'])
    (output/'plan.json').write_text(json.dumps(dict(commit=commit,plan=config,command=command),indent=2)+'\n')
    try:
        with (output/'stdout.log').open('wb') as stdout,(output/'stderr.log').open('wb') as stderr:
            process=subprocess.Popen(command,stdout=stdout,stderr=stderr,env=env,start_new_session=True)
            try:returncode=process.wait(timeout=timeout);status='process_completed'
            except subprocess.TimeoutExpired:
                import signal
                os.killpg(process.pid,signal.SIGKILL);process.wait();returncode=None;status='timeout'
    except OSError:raise ValueError('Native sandbox could not start') from None
    data=dict(status=status,returncode=returncode,commit=commit,language=language,
              archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
              evidence_kind=config['evidence_kind'],rules_covered=[],payment_validity='unknown',
              interpretation='Exit status is a regression observation, not a proof or confirmed vulnerability.',
              external_network='disabled by required namespace sandbox',generated_attack_inputs=0)
    (output/'results.json').write_text(json.dumps(data,indent=2)+'\n')
    return data
