"""Offline, explicit recovery of an interrupted review transport request.

Never reads credentials, calls providers, retries refusals, or edits old responses.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import re


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2)+'\n')


def verify_marker(out):
    marker=read(out/'transport-resume.json')
    name=marker['attempt_directory']
    if not isinstance(name,str) or not name.startswith('transport-attempt-') or Path(name).name!=name:
        raise ValueError('Invalid recovery attempt directory')
    for name, expected in marker['preserved_sha256'].items():
        path=out/name
        if Path(name).is_absolute() or '..' in Path(name).parts or not path.is_file() or digest(path)!=expected:
            raise ValueError('Preserved review checkpoint changed')
    return marker


def cached_judgments(out, current_input, instruction, check):
    # Same exact inputs and prompt are required before any old judgment is reused.
    security=str(Path(__file__).resolve().parent/'security')
    if security not in sys.path:sys.path.insert(0,security)
    from codex_api_user_spec import json_mode_input
    expected=json_mode_input(current_input)
    from context_encoding import pack_context
    packed_expected=json_mode_input(pack_context(current_input))
    result={}
    for i in range(1,4):
        label=f'judge{i}';path=out/(label+'.json')
        if not path.is_file():continue
        value=read(path);check(value)
        candidates=list(out.rglob(label+'.request.json'))
        def same_context(path):
            request=read(path)
            return ((request.get('input')==expected and request.get('instructions')==instruction) or
                    any(request.get('messages')==[dict(role='system',content=instruction),dict(role='user',content=user)]
                        for user in [expected,packed_expected]))
        matching=[p for p in candidates if same_context(p)]
        if not matching:raise ValueError('Saved judgment input/prompt differs; no paid request sent')
        # A validated checkpoint must also agree with an actual saved raw response.
        from evidence_format import normalize,documents
        if not any(p.with_name(label+'.response.txt').is_file() and
                   normalize(read(p.with_name(label+'.response.txt')),documents(current_input))==value for p in matching):
            raise ValueError('Saved judgment has no matching raw model response')
        result[label]=value
    return result


def prepare(plan_path, task):
    plan_path=Path(plan_path).resolve();plan=read(plan_path)
    journal_path=plan_path.parent/'journal.json';journal=read(journal_path)
    if journal['plan_sha256']!=digest(plan_path):raise ValueError('Plan changed')
    parts=task.split('/')
    if len(parts)!=3 or parts[2]!='review':raise ValueError('Recovery only supports an explicit review task')
    row=next((r for r in plan['versions'] if r['version_id']==parts[0]),None)
    previous=journal['tasks'].get(task)
    if not row or not previous or previous['status']!='failed':raise ValueError('Select the exact failed review task')
    if not re.fullmatch(r'[a-f0-9]{16}-[0-9]{2}',parts[1]):raise ValueError('Invalid rule')
    out=Path(row['folder'])/'04-consistency'/parts[1]
    if (out/'synthesis.json').exists():raise ValueError('Completed synthesis cannot be recovered as transport failure')
    usages=list(out.rglob('*.usage.json'))
    if not usages:raise ValueError('No saved provider usage')
    latest=max(usages,key=lambda p:p.stat().st_mtime_ns);usage=read(latest)
    if usage.get('status')!='transport_or_response_failure' or usage.get('http_status') is not None:
        raise ValueError('Only a transport failure may be explicitly continued; refusal/HTTP/schema failures remain stopped')
    label=latest.name.removesuffix('.usage.json')
    if latest.with_name(label+'.response.txt').exists():raise ValueError('A response exists; inspect it offline instead of resubmitting')
    request=latest.with_name(label+'.request.json')
    if not request.is_file() or usage.get('request_sha256')!=hashlib.sha256(json.dumps(read(request),ensure_ascii=False,separators=(',',':')).encode()).hexdigest():
        raise ValueError('Failed request identity mismatch')
    n=1
    while (plan_path.parent/f'recovery-transport-review-{n:03}').exists():n+=1
    backup=plan_path.parent/f'recovery-transport-review-{n:03}';backup.mkdir()
    shutil.copy2(journal_path,backup/'journal.before.json')
    if (out/'transport-resume.json').exists():shutil.copy2(out/'transport-resume.json',backup/'marker.before.json')
    preserved={str(p.relative_to(out)):digest(p) for p in out.rglob('*') if p.is_file() and p.name!='transport-resume.json'}
    attempt=1
    while (out/f'transport-attempt-{attempt:03}').exists():attempt+=1
    marker=dict(task=task,attempt_directory=f'transport-attempt-{attempt:03}',preserved_sha256=preserved,
                failed_usage=str(latest),backup=str(backup),provider_outcome='unknown',
                billing_note='The prior request may have been processed; a manual continuation can incur additional cost.',
                automatic_retry=False)
    write(out/'transport-resume.json',marker)
    journal['tasks'][task]=dict(status='transport_resume_prepared',previous_failure=previous,recovery_marker=str(out/'transport-resume.json'))
    journal['status']='awaiting_manual_transport_continuation';journal.pop('stop_reason',None)
    write(journal_path,journal)
    write(backup/'recovery.json',marker)
    return dict(task=task,status=journal['status'],backup=str(backup),models_called=0)
