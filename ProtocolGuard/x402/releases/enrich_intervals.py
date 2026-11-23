import json,difflib
import audit

def main():
    repo=audit.Repo();node=audit.Node();a=audit.Analyzer(repo,node)
    try:
        for i,path in enumerate(sorted((audit.BASE/'intervals').glob('*.json')),1):
            base,head=path.stem.split('_');changes=audit.interval(repo,a,base,head)
            for row in changes:
                for change in row.get('symbols_modified',[]):
                    before=set(change['before'].get('guards',[]));after=set(change['after'].get('guards',[]))
                    change['guards_added']=sorted(after-before);change['guards_removed']=sorted(before-after)
                if row['path'].startswith('specs/'):
                    before=repo.blob(row['before_blob']).splitlines() if row['before_blob'] else []
                    after=repo.blob(row['after_blob']).splitlines() if row['after_blob'] else []
                    row['spec_unified_diff']='\n'.join(difflib.unified_diff(before,after,fromfile=base+'/'+row['path'],tofile=head+'/'+row['path'],lineterm=''))
            # Commit subjects support navigation; they are not security conclusions.
            try:
                text=audit.git('log','--format=%H%x09%s',base+'..'+head).decode()
                commits=[dict(zip(('sha','subject'),line.split('\t',1))) for line in text.splitlines()]
            except Exception:
                source=audit.BASE/'official-compare-latest.json'
                commits=[{'sha':x['sha'],'subject':x['commit']['message'].splitlines()[0]} for x in json.loads(source.read_text()).get('commits',[])] if head.startswith('07c4') else []
            path.write_text(json.dumps({'baseline':base,'head':head,'changes':changes,'commits':commits,'interpretation':'structural diff; semantic review pending'},indent=2))
            print(i,path.stem[:18],flush=True)
    finally:repo.close();node.close()

if __name__=='__main__':main()
