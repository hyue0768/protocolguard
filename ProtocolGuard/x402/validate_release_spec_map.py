"""Validate saved tag/spec correspondence without network or target execution."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re

from map_release_specs import digest, role


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent / 'release-spec-map')
    a = p.parse_args()
    root = a.directory.resolve()
    read = lambda name: json.loads((root / name).read_text())
    mapping, capture, summary = read('mapping.json'), read('acquisition.json'), read('summary.json')
    rows = mapping['rows']
    assert len(rows) == len({r['tag'] for r in rows}) == summary['tag_count']
    captured = {r['name']: r['commit']['sha'] for r in capture['tags']}
    assert {r['tag']: r['code_commit'] for r in rows} == captured
    docs = {r['git_blob']: r for r in read('documents.json')}
    for oid, d in docs.items():
        data = (root / d['local_file']).read_bytes()
        assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid
        assert hashlib.sha256(data).hexdigest() == d['sha256']
    bundles = {}
    for file in (root / 'bundles').glob('*.json'):
        bundle = json.loads(file.read_text())
        entries = {r['path']: r['git_blob'] for r in bundle['documents']}
        assert digest(entries) == bundle['id'] == file.stem
        normative = {p: oid for p, oid in entries.items() if role(p) != 'supporting_index_or_template'}
        assert digest(normative) == bundle['normative_fingerprint']
        assert len(entries) == bundle['document_count']
        assert len(normative) == bundle['normative_document_count']
        for d in bundle['documents']:
            assert d['git_blob'] in docs
            assert d['local_file'] == docs[d['git_blob']]['local_file']
        bundles[bundle['id']] = bundle
    for row in rows:
        bundle = bundles[row['spec_bundle_id']]
        snapshot = read('snapshots/' + row['code_commit'] + '.json')
        assert snapshot['commit'] == row['code_commit']
        assert snapshot['spec_bundle_id'] == bundle['id']
        assert digest(snapshot['spec_entries']) == bundle['id']
        assert row['tag'] in bundle['tags'] and row['code_commit'] in bundle['commits']
        assert row['declared_core_protocol_versions'] == bundle['declared_core_protocol_versions']
        assert not row['registry_distribution_equivalence_verified']
        assert row['independently_released_spec_version'] is None
    with (root / 'mapping.csv').open() as f:
        csvrows = list(csv.DictReader(f))
    assert len(csvrows) == len(rows)
    assert {(r['tag'], r['code_commit'], r['spec_bundle_id']) for r in csvrows} == {(r['tag'], r['code_commit'], r['spec_bundle_id']) for r in rows}
    for file in root.glob('*.md'):
        text = file.read_text()
        anchors = set(re.findall(r'<a id="(ref-\d+)"></a>', text))
        cites = set(re.findall(r'\]\(#(ref-\d+)\)', text))
        assert anchors == cites, file.name
        for url in re.findall(r'\]\(([^)]+)\)', text):
            if not url.startswith(('#', 'https://', 'http://')):
                target = file.parent / url.partition('#')[0]
                if target != root / 'validation.json':
                    assert target.exists(), (file, url)
    result = dict(status='passed', tags=len(rows), code_commits=len({r['code_commit'] for r in rows}),
                  spec_bundles=len(bundles), spec_blobs=len(docs),
                  tag_commit_equality_to_capture=True, spec_blob_git_and_sha256_checks=True,
                  bundle_fingerprint_checks=True, csv_json_consistency=True,
                  local_document_links_and_citations=True, model_calls=0, target_executions=0)
    output = root / 'validation.json'
    if not output.exists():
        output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
