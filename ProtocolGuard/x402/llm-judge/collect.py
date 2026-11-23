"""Offline release evidence inventory; never executes code or contacts a model.

File reading/hashing is not a semantic audit. Expert-reviewed evidence is
recorded separately; unreviewed languages/mechanisms remain explicitly unknown.
"""
import collections
import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
sys.path.insert(0,str(BASE))
from map_release_specs import Sources


def read(path):return json.loads(path.read_text())


def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():raise ValueError('Evidence output exists; no overwrite: '+str(path))
    path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n')


def component(path):
    patterns=[
      ('ts_evm_v1',r'typescript/packages/(?:legacy/)?x402/src/schemes/exact/evm/facilitator.ts$'),
      ('ts_evm_v2',r'typescript/packages/mechanisms/evm/src/exact/facilitator/(?:scheme|eip3009).ts$'),
      ('ts_evm_v1_adapter',r'typescript/packages/mechanisms/evm/src/exact/v1/facilitator/scheme.ts$'),
      ('go_evm_v2',r'go/mechanisms/evm/exact/facilitator/scheme.go$'),
      ('py_evm_v2',r'python/x402/mechanisms/evm/exact/facilitator.py$'),
      ('ts_http_middleware',r'typescript/packages/(?:x402-express|http/express)/src/index.ts$'),
      ('ts_resource_server',r'typescript/packages/core/src/server/x402ResourceServer.ts$'),
      ('ts_http_server',r'typescript/packages/core/src/http/x402HTTPResourceServer.ts$'),
      ('ts_http_facilitator',r'typescript/packages/core/src/http/httpFacilitatorClient.ts$'),
      ('ts_pending_store',r'typescript/packages/core/src/facilitator/pendingSettlementStore.ts$'),
      ('ts_signature',r'typescript/packages/mechanisms/evm/src/shared/verifySignature.ts$'),
      ('ts_receipt',r'typescript/packages/mechanisms/evm/src/shared/settleReceipt.ts$'),
      ('ts_eip3009_utils',r'typescript/packages/mechanisms/evm/src/exact/facilitator/eip3009-utils.ts$'),
      ('ts_asset_cache',r'typescript/packages/mechanisms/evm/src/assetCache.ts$'),
      ('ts_identifier',r'typescript/packages/extensions/src/payment-identifier/(?:validation|index).ts$'),
      ('ts_svm',r'typescript/packages/mechanisms/svm/src/exact/facilitator/scheme.ts$'),
      ('contracts',r'contracts/evm/src/(?!mocks/).*\.sol$'),
    ]
    return next((name for name,pattern in patterns if re.fullmatch(pattern,path)),None)


def implementation(path):
    parts=Path(path).parts
    return (Path(path).suffix in {'.ts','.tsx','.go','.py','.sol','.rs','.java','.js','.cjs','.mjs'}
            and not any(p in {'tests','test','e2e','examples','demo','demos','site','docs','node_modules','vendor'} for p in parts)
            and not re.search(r'([._]test|[._]spec)\.',path))


def main():
    rows=read(BASE/'version-audits/index.json')['versions'];grouped=collections.defaultdict(list)
    for row in rows:grouped[row['commit']].append(row)
    entries=[];variants={};specs={};extra={};sources=Sources()
    try:
        for commit,refs in grouped.items():
            row=refs[0];folder=Path(row['folder']);meta=read(folder/'audit.json')
            source=BASE/'version-audits/shared/code'/commit/'source';indexed=read(source.parent/'files.json')
            files=[]
            for item in indexed:
                path=source/item['file'];raw=path.read_bytes()
                if hashlib.sha256(raw).hexdigest()!=item['sha256'] or hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=item['git_blob']:
                    raise ValueError('Source identity mismatch')
                entry=dict(file=item['file'],git_blob=item['git_blob'],sha256=item['sha256'],bytes=len(raw),local_file=str(path),component=component(item['file']),semantic_review='not_inferred_from_reading_or_hashing')
                files.append(entry)
                label=entry['component']
                if label:
                    key=(label,entry['git_blob'])
                    if key not in variants:variants[key]=dict(component=label,git_blob=entry['git_blob'],local_file=str(path),file=item['file'],first_commit=commit,commits=[],lines=len(raw.splitlines()))
                    variants[key]['commits'].append(commit)
            # Existing parser inventory omitted Java/JS. Inspect local tracked
            # code objects too; missing objects are reported, never fetched.
            tree=sources.tree(commit);indexed_paths={item['file'] for item in indexed};additional=[];unavailable=[]
            for path,oid in tree.items():
                if path in indexed_paths or not implementation(path):continue
                try:raw=sources.blob(commit,path,oid)
                except (OSError,ValueError):unavailable.append(dict(file=path,git_blob=oid));continue
                additional.append(dict(file=path,git_blob=oid,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),semantic_review='not_semantically_reviewed'))
                extra[oid]=dict(file=path,bytes=len(raw))
            bundle=read(folder/'01-spec/bundle.json')
            for document in bundle['documents']:
                path=BASE/'release-spec-map'/document['local_file'];raw=path.read_bytes()
                if hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()!=document['git_blob']:raise ValueError('Spec identity mismatch')
                specs[document['git_blob']]=dict(path=document['path'],git_blob=document['git_blob'],local_file=str(path),lines=len(raw.splitlines()))
            entry=dict(commit=commit,date=meta['mapping']['commit_date'],tag_references=[r['tag'] for r in refs],spec_bundle_id=row['spec_bundle_id'],
                       indexed_files=files,additional_local_code=additional,unavailable_code=unavailable,
                       language_counts=dict(collections.Counter(Path(f['file']).suffix for f in files+additional)),
                       reviewed_scope='see separate expert findings; reading bytes is only inventory')
            entries.append(entry)
        entries.sort(key=lambda x:datetime.datetime.fromisoformat(x['date']))
        order={entry['commit']:i for i,entry in enumerate(entries)}
        variants=list(variants.values());variants.sort(key=lambda x:(x['component'],min(order[c] for c in x['commits'])))
        for variant in variants:
            variant['commits'].sort(key=order.get);variant['first_commit']=variant['commits'][0]
        save(HERE/'inputs.json',dict(tag_references=len(rows),commits=entries,
            totals=dict(indexed_file_occurrences=sum(len(e['indexed_files']) for e in entries),unique_indexed_blobs=len({f['git_blob'] for e in entries for f in e['indexed_files']}),
                        additional_code_occurrences=sum(len(e['additional_local_code']) for e in entries),unique_additional_blobs=len(extra),missing_code_occurrences=sum(len(e['unavailable_code']) for e in entries),spec_blobs=len(specs)),
            model_calls=0,target_executions=0))
        save(HERE/'component-variants.json',variants);save(HERE/'spec-variants.json',list(specs.values()))
        print(json.dumps(dict(commits=len(entries),tags=len(rows),component_variants=len(variants),extra_blobs=len(extra),missing=sum(len(e['unavailable_code']) for e in entries))))
    finally:sources.close()


if __name__=='__main__':main()
