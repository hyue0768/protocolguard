"""Evidence/report integrity checks only; never executes audited source."""
import hashlib
import json
from pathlib import Path
import re

HERE=Path(__file__).resolve().parent


def main():
    inputs=json.loads((HERE/'inputs.json').read_text());observations=json.loads((HERE/'source-observations-v2.json').read_text())
    cases=json.loads((HERE/'expert-cases.json').read_text());completed=json.loads((HERE/'completion.json').read_text())
    commits={c['commit'] for c in inputs['commits']}
    assert len(commits)==81 and completed['commit_reports']==81 and completed['tag_reports']==750
    assert len(list((HERE/'commits').glob('*/analysis.md')))==81
    assert len(list((HERE/'releases').glob('*/analysis.md')))==750
    assert '1a084343e165d6f61b60b34f6146d6e4a4a7f3ca' not in commits
    quotes=0
    for evidence in observations['evidence']+[e for c in cases for e in c['evidence']]:
        raw=Path(evidence['local_file']).read_bytes()
        assert hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==evidence['git_blob']
        lines=raw.decode().splitlines()
        if 'end' in evidence:
            assert evidence['quote'] in '\n'.join(lines[evidence['line']-1:evidence['end']])
        else:assert evidence['quote']==lines[evidence['line']-1]
        quotes+=1
    for c in cases:assert set(c['applicable_commits'])<=commits and c['confirmed_vulnerability'] is False
    for p in HERE.rglob('*.md'):
        text=p.read_text();labels=re.findall(r'\[\[(\d+)\]\]\(#ref-\1\)',text)
        first=list(dict.fromkeys(labels));assert first==[str(n) for n in range(1,len(first)+1)],p
        anchors=re.findall(r'<a id="ref-(\d+)"></a>',text)
        assert set(labels)==set(anchors),(p,'citation anchor mismatch')
        assert text.count('## References')==1,(p,'bibliography missing/duplicate')
        assert '|\n\n|' not in text,(p,'broken table')
        for link in re.findall(r'\]\(([^)]+)\)',text):
            link=link.strip('<>')
            if link.startswith(('#','http://','https://')):continue
            assert (p.parent/link).exists(),(p,link)
    for p in (HERE/'releases').glob('*/evolution.json'):
        d=json.loads(p.read_text())
        if d['status']=='same_source_commit':
            assert not d['changed_files'] and not d['added_files'] and not d['removed_files']
            assert not d['new_source_forms'] and not d['removed_source_forms']
        assert d['semantic_change_verified'] is False
    result=dict(status='passed',commit_reports=81,tag_reports=750,exact_quote_checks=quotes,
                markdown_files=len(list(HERE.rglob('*.md'))),expert_cases=len(cases),
                report_links_and_citations='passed',same_commit_no_false_upgrade='passed',
                semantic_exhaustiveness_proven=False,models_called=0,target_executions=0)
    path=HERE/'validation.json'
    if path.exists():raise ValueError('Validation exists; no overwrite')
    path.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))


if __name__=='__main__':main()
