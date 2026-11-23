"""Check every generated report, link, source interval, and live-tag coverage."""
import json,re
from pathlib import Path
BASE=Path(__file__).resolve().parent
errors=[]
files=list((BASE/'versions').glob('*.md'))+list((BASE/'intervals').glob('*.md'))+[BASE/'README.md',BASE/'FINDINGS.md',BASE/'ALL-RELEASES.md']
for path in files:
    s=path.read_text();used=re.findall(r'\[\[(\d+)\]\]\(#ref-\1\)',s);anchors=re.findall(r'<a id="ref-(\d+)"></a>',s)
    if set(used)!=set(anchors) or list(dict.fromkeys(used))!=[str(i) for i in range(1,len(anchors)+1)]:errors.append(str(path)+' citation anchors')
    for link in re.findall(r'\]\(([^)]+)\)',s):
        if '://' in link or link.startswith('#'):continue
        if not (path.parent/link.split('#')[0]).exists():errors.append(str(path)+' missing '+link)
live=json.loads((BASE/'live-tags.json').read_text())['tags'];data=json.loads((BASE/'results.json').read_text())
if {r['tag'] for r in data['tags']}!={r['name'] for r in live}:errors.append('live tag coverage mismatch')
result={'markdown_files':len(files),'tag_reports':len(list((BASE/'versions').glob('*.md'))),'interval_diffs':len(list((BASE/'intervals').glob('*.implementation.diff.gz'))),'errors':errors}
(BASE/'documentation-validation.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result,indent=2))
if errors:raise SystemExit(1)
