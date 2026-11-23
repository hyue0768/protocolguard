"""Map official code tags to their co-located specification snapshots.

Read-only source access. Writes a new output directory; no checkout, fetch,
models, target execution, or registry-package downloads.
"""
import argparse
import collections
import csv
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.parse
import urllib.request

BASE = Path(__file__).resolve().parent
PROJECT = BASE.parents[1]
HISTORY = BASE / 'releases'
ENV = {'PATH': os.defpath, 'GIT_NO_LAZY_FETCH': '1', 'GIT_OPTIONAL_LOCKS': '0',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
GIT = shutil.which('git')
REPO = 'https://github.com/x402-foundation/x402'
API = 'https://api.github.com/repos/x402-foundation/x402'


def read(path):
    return json.loads(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def get(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'ProtocolGuard-release-spec-inventory',
                                               'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=40) as response:
        return json.load(response)


class Sources:
    def __init__(self):
        self.git = HISTORY / 'upstream.git'
        self.process = subprocess.Popen([GIT, '-C', str(self.git), 'cat-file', '--batch'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=ENV)
        self.cache = {}
        self.snapshots = {}
        for prefix, filename in [('07c4caf', 'upstream-tree.json'), ('2178d4b', 'upstream-tree-latest.json')]:
            tree = read(BASE / filename)
            folder = PROJECT / ('x402_upstream_20261113_' + prefix + '_snapshot')
            self.snapshots[tree['sha']] = ({x['path']: x['sha'] for x in tree['tree'] if x['type'] == 'blob'}, folder)
        target = read(BASE / 'security/target.json')
        tree = read(BASE / 'security/tree.json')
        self.snapshots[target['commit']] = ({x['path']: x['sha'] for x in tree['tree'] if x['type'] == 'blob'}, Path(target['upstream']))

    def tree(self, sha):
        if sha in self.snapshots:
            return self.snapshots[sha][0]
        result = subprocess.run([GIT, '-C', str(self.git), 'ls-tree', '-r', '-z', sha],
                                env=ENV, capture_output=True, check=False)
        if result.returncode:
            raise ValueError('Commit tree unavailable locally; no automatic fetch: ' + sha)
        entries = {}
        for row in result.stdout.split(b'\0'):
            if not row:
                continue
            meta, path = row.split(b'\t', 1)
            _, kind, obj = meta.split()
            if kind == b'blob':
                entries[path.decode()] = obj.decode()
        return entries

    def blob(self, sha, path, oid):
        if oid in self.cache:
            return self.cache[oid]
        cache = HISTORY / 'blob-cache' / (oid + '.gz')
        if cache.exists():
            raw = gzip.decompress(cache.read_bytes())
        elif sha in self.snapshots:
            raw = (self.snapshots[sha][1] / path).read_bytes()
        else:
            self.process.stdin.write((oid + '\n').encode())
            self.process.stdin.flush()
            head = self.process.stdout.readline().split()
            if len(head) != 3 or head[1] != b'blob':
                raise ValueError('Spec blob missing locally; no automatic fetch: ' + oid)
            raw = self.process.stdout.read(int(head[2]))
            if self.process.stdout.read(1) != b'\n':
                raise ValueError('Git batch output framing error')
        if hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != oid:
            raise ValueError('Spec Git blob identity mismatch: ' + path)
        self.cache[oid] = raw
        return raw

    def close(self):
        self.process.stdin.close()
        self.process.wait()
        self.process.stdout.close()


def is_spec(path):
    return path.startswith('specs/') and Path(path).suffix in ['.md', '.mdx']


def role(path):
    name = Path(path).name
    if name in ['README.md', 'CONTRIBUTING.md'] or 'template' in name:
        return 'supporting_index_or_template'
    if name.startswith('x402-specification'):
        return 'core'
    if '/schemes/' in path:
        return 'scheme'
    if '/extensions/' in path:
        return 'extension'
    if '/transports' in path:
        return 'transport'
    return 'other_spec_document'


def digest(entries):
    value = '\n'.join(p + '\0' + oid for p, oid in sorted(entries.items())).encode()
    return hashlib.sha256(value).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=BASE / 'release-spec-map')
    p.add_argument('--refresh-tags', action='store_true', help='read public official tag/release metadata; no inference')
    a = p.parse_args()
    out = a.output.resolve()
    if out.exists():
        p.error('Output exists; select a new directory. No overwrite or resume.')
    inventory = read(HISTORY / 'inventory.json')
    old_by_tag = {x['tag']: x for x in inventory}
    scope = {x['tag']: x for x in read(HISTORY / 'package-scope.json')}
    if a.refresh_tags:
        tags = []
        pages = []
        for page in range(1, 31):
            rows = get(API + '/tags?per_page=100&page=' + str(page))
            if not isinstance(rows, list):
                raise ValueError('Unexpected tag response')
            pages.append(dict(page=page, count=len(rows)))
            tags.extend(rows)
            if len(rows) < 100:
                break
        else:
            raise ValueError('Tag pagination cap reached; refusing incomplete all-tags claim')
        releases = get(API + '/releases?per_page=100')
        head = get(API + '/commits/main')
        checked = datetime.datetime.now(datetime.timezone.utc).isoformat()
        acquisition = dict(source='live_public_github_api', checked_at=checked, pages=pages,
                           tag_count=len(tags), tags=tags, github_releases_first_page=releases,
                           releases_pagination_complete=len(releases) < 100,
                           main=dict(sha=head['sha'], commit_date=head['commit']['committer']['date']))
    else:
        existing = read(HISTORY / 'live-tags.json')
        tags = existing['tags']
        acquisition = dict(source='existing_official_api_capture', checked_at=existing['checked_at'],
                           tag_count=len(tags), tags=tags,
                           github_releases_status='not_refreshed_by_this_run')
    names = [x['name'] for x in tags]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate tag names across pages; collection changed during pagination')
    # Resolve all commits/specs before creating output. Unknown new objects do
    # not silently inherit another version's specification.
    source = Sources()
    snapshots, docs, bundles = {}, {}, {}
    try:
        for tag in tags:
            sha = tag['commit']['sha']
            if sha in snapshots:
                continue
            tree = source.tree(sha)
            specs = {path: oid for path, oid in tree.items() if is_spec(path)}
            normative = {path: oid for path, oid in specs.items() if role(path) != 'supporting_index_or_template'}
            bundle = digest(specs)
            declared = []
            core_paths = []
            for path, oid in sorted(specs.items()):
                raw = source.blob(sha, path, oid)
                content_hash = hashlib.sha256(raw).hexdigest()
                if oid not in docs:
                    docs[oid] = dict(git_blob=oid, sha256=content_hash, bytes=len(raw),
                                     local_file='documents/' + oid + '.md', source_examples=[])
                if len(docs[oid]['source_examples']) < 3:
                    docs[oid]['source_examples'].append(dict(commit=sha, path=path))
                if role(path) == 'core':
                    core_paths.append(path)
                    versions = re.findall(r'Protocol\s+Version\s*\*?\*?\s*:\s*\*?\*?\s*([0-9]+(?:\.[0-9]+)?)', raw.decode(), re.I)
                    declared.extend(versions)
            if bundle not in bundles:
                bundles[bundle] = dict(id=bundle, normative_fingerprint=digest(normative),
                    document_count=len(specs), normative_document_count=len(normative),
                    declared_core_protocol_versions=sorted(set(declared)), core_documents=core_paths,
                    documents=[dict(path=path, git_blob=oid, role=role(path), local_file=docs[oid]['local_file']) for path, oid in sorted(specs.items())],
                    commits=[], tags=[])
            bundles[bundle]['commits'].append(sha)
            snapshots[sha] = dict(commit=sha, tracked_blob_count=len(tree),
                source_tree_url=REPO + '/tree/' + sha,
                source_archive_url='https://codeload.github.com/x402-foundation/x402/tar.gz/' + sha,
                full_code_archive_downloaded_by_this_run=False,
                spec_bundle_id=bundle, spec_entries=specs)
    finally:
        source.close()
    rows = []
    for tag in tags:
        name, sha = tag['name'], tag['commit']['sha']
        old = old_by_tag.get(name, {})
        old_scope = scope.get(name, {})
        snapshot = snapshots[sha]
        bundle = bundles[snapshot['spec_bundle_id']]
        bundle['tags'].append(name)
        baseline = old.get('baseline_sha')
        previous = snapshots.get(baseline, {}).get('spec_entries')
        changes = None
        if previous is not None:
            current = snapshot['spec_entries']
            changes = dict(added=sorted(set(current)-set(previous)), removed=sorted(set(previous)-set(current)),
                           modified=sorted(k for k in set(current)&set(previous) if current[k] != previous[k]))
        old_metadata_matches_sha = old_scope.get('sha') == sha
        rows.append(dict(tag=name, code_commit=sha, family=old.get('family', name.rsplit('@v', 1)[0]),
            commit_date=old.get('commit_date') if old.get('sha') == sha else None,
            publication_time=old.get('publication_time'), publication_time_source='historical registry capture; not refreshed',
            mapping_kind='co_located_spec_snapshot_not_independent_compatibility_claim',
            spec_bundle_id=bundle['id'], normative_fingerprint=bundle['normative_fingerprint'],
            declared_core_protocol_versions=bundle['declared_core_protocol_versions'],
            core_spec_status=('core_document_with_explicit_version_header' if bundle['declared_core_protocol_versions']
                              else 'core_document_present_version_header_missing') if bundle['core_documents']
                              else 'no_core_spec_document_in_this_tree',
            spec_document_count=bundle['document_count'], normative_document_count=bundle['normative_document_count'],
            source_tree_url=snapshot['source_tree_url'], source_archive_url=snapshot['source_archive_url'],
            same_commit_specs_url=REPO + '/tree/' + sha + '/specs',
            historical_package_scope=old_scope if old_metadata_matches_sha else None,
            registry_distribution_equivalence_verified=False,
            independently_released_spec_version=None,
            package_protocol_version_support='not_inferred_from_tag_or_document_presence',
            baseline_tag=old.get('baseline_tag'), baseline_commit=baseline,
            spec_changes_against_package_line_baseline=changes,
            historical_version_report='../releases/versions/' + str(inventory.index(old)+1).zfill(4)+'.md' if old and old.get('sha') == sha else None,
            cached_inventory_commit_matches=old.get('sha') == sha))
    rows.sort(key=lambda r: (r.get('commit_date') or '', r['tag']))
    out.mkdir(parents=True)
    (out / 'documents').mkdir()
    (out / 'bundles').mkdir()
    (out / 'snapshots').mkdir()
    for oid, doc in docs.items():
        (out / doc['local_file']).write_bytes(source.cache[oid])
    for id, bundle in bundles.items():
        save(out / 'bundles' / (id + '.json'), bundle)
    for sha, snapshot in snapshots.items():
        save(out / 'snapshots' / (sha + '.json'), snapshot)
    save(out / 'acquisition.json', acquisition)
    save(out / 'documents.json', list(docs.values()))
    save(out / 'mapping.json', dict(schema_version='1.0', repository=REPO,
         checked_at=acquisition['checked_at'], mapping_kind='co_located_spec_snapshot',
         scope_note='All tags at capture time. Code tags are not necessarily stable releases; package versions are not protocol versions. Co-location is not semantic compliance or an independent spec release.',
         registry_tarballs_scope='Not downloaded or compared; retain historical package metadata exceptions.', rows=rows))
    fields=['tag','family','code_commit','commit_date','publication_time','spec_bundle_id',
            'normative_fingerprint','declared_core_protocol_versions','spec_document_count',
            'normative_document_count','core_spec_status','source_archive_url','same_commit_specs_url']
    with (out / 'mapping.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            small = {k: row[k] for k in fields}
            small['declared_core_protocol_versions'] = ','.join(small['declared_core_protocol_versions'])
            writer.writerow(small)
    summary = dict(tag_count=len(rows), code_commits=len(snapshots), spec_bundles=len(bundles),
        normative_bundles=len({b['normative_fingerprint'] for b in bundles.values()}),
        unique_spec_blobs=len(docs), tags_without_core_document=sum(not bundles[r['spec_bundle_id']]['core_documents'] for r in rows),
        tags_with_core_but_no_version_header=sum(r['core_spec_status']=='core_document_present_version_header_missing' for r in rows),
        package_metadata_exceptions=sum(r['historical_package_scope'] is not None and r['historical_package_scope']['status']=='no_matching_npm_metadata_in_snapshot' for r in rows),
        all_known_inventory_tags_present=set(old_by_tag)<=set(names),
        new_tags=sorted(set(names)-set(old_by_tag)), missing_prior_tags=sorted(set(old_by_tag)-set(names)),
        changed_tag_targets=[r['tag'] for r in rows if r['tag'] in old_by_tag and not r['cached_inventory_commit_matches']],
        spec_blob_identity_checks='passed', models_called=0, target_executions=0)
    save(out / 'summary.json', summary)
    # This table contains local evidence, not external scholarly claims.
    lines=['# Code tag 与同提交 specification 对应表', '',
           '每行对应一个官方 tag。spec bundle 指同一提交附带的规范集合，不是独立发布的兼容性认证。输入与生成方法见 README。[[1]](#ref-1)', '',
           '| Tag | Code commit | Spec bundle | Core 声明 | 规范文档数 | 同发布线基线下规范变化 | 历史包元数据状态 |',
           '| --- | --- | --- | --- | --- | --- | --- |']
    for row in rows:
        diff = row['spec_changes_against_package_line_baseline']
        delta = ('+'+str(len(diff['added']))+' / ~'+str(len(diff['modified']))+' / -'+str(len(diff['removed']))) if diff is not None else '无可比较基线'
        status = (row['historical_package_scope'] or {}).get('status', '未核对')
        versions = ','.join(row['declared_core_protocol_versions']) or '未声明/缺失'
        lines.append('| `'+row['tag']+'` | ['+row['code_commit'][:12]+'](snapshots/'+row['code_commit']+'.json) | ['+row['spec_bundle_id'][:12]+'](bundles/'+row['spec_bundle_id']+'.json) | '+versions+' | '+str(row['normative_document_count'])+' | '+delta+' | '+status+' |')
    lines += ['', '## References', '', '<a id="ref-1"></a>[1] ProtocolGuard 项目，“发布源码与规范对应的采集和方法”，2026。[README](README.md) [采集](acquisition.json) [完整映射](mapping.json)', '']
    (out / 'ALL-MAPPINGS.md').write_text('\n'.join(lines))
    print(json.dumps(dict(output=str(out), **summary), indent=2))


if __name__ == '__main__':
    main()
