"""Offline, pinned TS whole-function context slices for user security goals.

Does not execute target code, call models, or run dynamic verification.
Output must be a new directory so historical artifacts cannot be overwritten.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess

BASE = Path(__file__).resolve().parent
PG = BASE.parents[1]
ROOT = PG.parent
PIN = '1a084343e165d6f61b60b34f6146d6e4a4a7f3ca'
PREFIX = 'typescript/packages/'
SERVER = PREFIX + 'core/src/server/x402ResourceServer.ts'
HTTP = PREFIX + 'core/src/http/x402HTTPResourceServer.ts'
FAC = PREFIX + 'core/src/http/httpFacilitatorClient.ts'
FLOW = PREFIX + 'core/src/server/paymentFlow.ts'
EXPRESS = PREFIX + 'http/express/src/index.ts'
FETCH = PREFIX + 'http/fetch/src/index.ts'
CLIENT = PREFIX + 'core/src/client/x402Client.ts'
EVM = PREFIX + 'mechanisms/evm/src/'
VERIFY = EVM + 'exact/facilitator/eip3009.ts'
UTILS = EVM + 'exact/facilitator/eip3009-utils.ts'
SIGN = EVM + 'shared/verifySignature.ts'
RECEIPT = EVM + 'shared/settleReceipt.ts'
STORE = PREFIX + 'core/src/facilitator/pendingSettlementStore.ts'
IDENT = PREFIX + 'extensions/src/payment-identifier/'


def sel(file, *names):
    return [file + '::' + name for name in names]


def mappings(spec, payment_validity_only=False):
    goals = {x['id']: x for x in spec['payment_validity_goals']}
    props = {x['id']: x for x in spec.get('formal_properties', [])}
    rows = []

    def add(id, source, rule, fields, handlers, context, limits):
        rows.append(dict(id=id, source_json_pointer=source, rule=rule,
                         req_type='PaymentPayload / PaymentRequirements', req_fields=fields,
                         res_type='VerifyResponse / SettleResponse / HTTP response', res_fields=[],
                         basis='user_reconstructed_goal_not_automatically_official_MUST',
                         status='mapped_for_review_unverified', handlers=handlers,
                         context=context, limits=limits))

    add('PAYER_AUTHORIZATION', '/payment_validity_goals/0', goals['PAYER_AUTHORIZATION']['predicate'],
        ['signature', 'authorization.from', 'authorization.to', 'authorization.value'],
        sel(VERIFY, 'verifyEIP3009', 'settleEIP3009'),
        sel(SIGN, 'verifyTypedDataSignature', 'classifyErc6492Payer') +
        sel(EVM + 'exact/client/eip3009.ts', 'createEIP3009Payload', 'signEIP3009Authorization') +
        sel(SERVER, 'x402ResourceServer.verifyPayment', 'x402ResourceServer.invokeFacilitator'),
        ['EOA primary scope; contract wallets, delegates and counterfactual branches require separate review.',
         'Signer implementations and deployed contract authorization are external context.'])
    add('PAYMENT_BINDING', '/payment_validity_goals/1', goals['PAYMENT_BINDING']['predicate'],
        ['accepted', 'asset', 'amount', 'payTo', 'network', 'validAfter', 'validBefore'],
        sel(SERVER, 'x402ResourceServer.findMatchingRequirements', 'paymentRequirementsMatchAccepted') + sel(VERIFY, 'verifyEIP3009'),
        sel(SERVER, 'x402ResourceServer.buildPaymentRequirements', 'x402ResourceServer.verifyPayment') +
        sel(EVM + 'exact/client/eip3009.ts', 'signEIP3009Authorization'),
        ['Do not strengthen monetary/advertised-term binding into cryptographic URL binding.', 'V1 branches in retained functions are context, not V1 coverage.'])
    add('REPLAY_RESISTANCE', '/payment_validity_goals/2', goals['REPLAY_RESISTANCE']['predicate'],
        ['authorization.nonce', 'authorization.from', 'asset', 'network', 'transaction'],
        sel(VERIFY, 'settleEIP3009', 'awaitEIP3009Settlement') + sel(RECEIPT, 'withPendingSettlementStore'),
        sel(STORE, 'InMemoryPendingSettlementStore.get', 'InMemoryPendingSettlementStore.set', 'InMemoryPendingSettlementStore.delete') +
        sel(UTILS, 'executeTransferWithAuthorization', 'verifyEip3009TransferEvent') +
        sel(SERVER, 'x402ResourceServer.settleWithPendingRetry'),
        ['Authoritative nonce consumption is a deployed ledger/contract assumption.', 'Submission counts, success responses and settled ledger transfers differ.', 'Cross-process storage and concurrency are unresolved deployment context.'])
    if payment_validity_only:
        return rows
    common = sel(EXPRESS, 'paymentMiddlewareFromHTTPServer') + sel(HTTP, 'x402HTTPResourceServer.processHTTPRequest', 'x402HTTPResourceServer.processSettlement')
    server_context = sel(SERVER, 'x402ResourceServer.verifyPayment', 'x402ResourceServer.settlePayment', 'x402ResourceServer.settlePaymentInternal', 'x402ResourceServer.runAfterVerifyHooks', 'x402ResourceServer.dispatchVerifiedPaymentCanceled') + sel(FLOW, 'resolvePaymentFlow', 'resolvePaymentFlowPhases', 'resolveFailurePathSettlement')
    add('SERVER_PROTECTION_AGAINST_CLIENT', '/formal_properties/0',
        'In HonestF/MalC/HonestS, protected resource delivery requires an earlier matching authoritative settlement.',
        ['sid', 'res', 'tx', 'paymentFlow'], common, server_context + sel(VERIFY, 'verifyEIP3009', 'settleEIP3009'),
        ['Setup honesty and adversary behavior are model assumptions.', 'Define delivery as protected bytes separately from handler side effects.', 'Retained upfront/authorization branches require applicability review.'])
    add('CLIENT_PROTECTION_AGAINST_SERVER', '/formal_properties/1',
        'In HonestF/HonestC/MalS, settlement requires later receipt of the intended resource.',
        ['sid', 'res', 'tx', 'tx2'], sel(FETCH, 'wrapFetchWithPayment'),
        common + sel(CLIENT, 'x402Client.createPaymentPayload', 'x402Client.handlePaymentResponse') + sel(HTTP, 'x402HTTPResourceServer.createCompletedSettlementHeaders'),
        ['An arbitrary malicious server is outside SDK enforcement.', 'Static context cannot prove eventual delivery.', 'Preserve existential tx2; it need not equal tx in the supplied formula.'])
    add('SERVER_PROTECTION_AGAINST_FACILITATOR', '/formal_properties/2',
        'In MalF/HonestC/HonestS, protected resource delivery requires earlier authoritative settlement independently of facilitator reports.',
        ['success', 'isValid', 'transaction', 'res'], common + sel(FAC, 'HTTPFacilitatorClient.verify', 'HTTPFacilitatorClient.settle'),
        server_context + sel(RECEIPT, 'waitAndReturnSettleResponse') + sel(UTILS, 'verifyEip3009TransferEvent'),
        ['Facilitator success is a report, not independent ledger evidence.', 'Honest facilitator receipt-checking code cannot establish malicious facilitator correctness.'])
    add('REQUEST_IDEMPOTENCY_CONTEXT', '/documented_mechanisms_as_described_by_user/2',
        'Review payment-identifier validation and integration points for idempotent retries without equating request deduplication to ledger replay resistance.',
        ['extensions.payment-identifier', 'id', 'request fingerprint'],
        sel(IDENT + 'resourceServer.ts', 'declarePaymentIdentifierExtension') + sel(IDENT + 'validation.ts', 'validatePaymentIdentifierRequirement', 'extractAndValidatePaymentIdentifier'),
        sel(SERVER, 'x402ResourceServer.validateExtensions'),
        ['Supporting context, not an additional formal theorem.', 'Application idempotency stores and fingerprint policies are not supplied; absence in this slice does not establish absence in the deployment.'])
    for row in rows:
        if row['id'] in props:
            row['formal_property'] = props[row['id']]
    return rows


# Parse syntax only. Never import/execute upstream TS. Resolve only unambiguous
# same-file identifier calls; methods/imports/dynamic dispatch remain explicit gaps.
AST_JS = r'''
const fs=require('fs'),ts=require(process.argv[1]);
const req=JSON.parse(fs.readFileSync(0,'utf8')),out=[];
for(const file of req.files){
 const text=fs.readFileSync(req.root+'/'+file,'utf8');
 const ast=ts.createSourceFile(file,text,ts.ScriptTarget.Latest,true);
 if(ast.parseDiagnostics.length)throw Error('Syntax diagnostics: '+file);
 const functions=[],imports=[];
 function walk(n,scope=''){
  if(ts.isImportDeclaration(n))imports.push(n.getText(ast));
  if((ts.isFunctionDeclaration(n)||ts.isMethodDeclaration(n)||ts.isConstructorDeclaration(n))&&n.body){
   const name=ts.isConstructorDeclaration(n)?'constructor':n.name?n.name.getText(ast):'<anonymous>';
   const calls=[];function visit(x){if(ts.isCallExpression(x))calls.push({expression:x.expression.getText(ast),local_identifier:ts.isIdentifier(x.expression)?x.expression.text:null,line:ast.getLineAndCharacterOfPosition(x.getStart(ast)).line+1});ts.forEachChild(x,visit);}visit(n.body);
   functions.push({selector:file+'::'+scope+name,name,qualified:scope+name,start:ast.getLineAndCharacterOfPosition(n.getStart(ast)).line+1,end:ast.getLineAndCharacterOfPosition(n.end).line+1,calls});
  }
  ts.forEachChild(n,c=>walk(c,ts.isClassDeclaration(n)&&n.name?scope+n.name.text+'.':scope));
 }walk(ast);out.push({file,imports,functions});
}process.stdout.write(JSON.stringify(out));
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=BASE / 'user-spec-slices')
    parser.add_argument('--spec', type=Path, default=BASE / 'user-security-spec.json')
    parser.add_argument('--payment-validity-only', action='store_true',
                        help='map exactly the three payer authorization/binding/replay goals')
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists():
        parser.error('Output already exists; select a new --output directory to preserve results.')
    spec_path = args.spec.resolve()
    spec = json.loads(spec_path.read_text())
    target = json.loads((BASE / 'target.json').read_text())
    upstream = Path(target['upstream']).resolve()
    tree = json.loads((BASE / 'tree.json').read_text())
    provenance = json.loads((upstream / 'UPSTREAM_PROVENANCE.json').read_text())
    if target['commit'] != PIN or provenance['commit'] != PIN or tree['sha'] != PIN or tree.get('truncated'):
        raise ValueError('Pinned target identity mismatch or incomplete tree')
    blobs = {x['path']: x['sha'] for x in tree['tree'] if x['type'] == 'blob'}
    if args.payment_validity_only:
        expected = ['PAYER_AUTHORIZATION', 'PAYMENT_BINDING', 'REPLAY_RESISTANCE']
        if [r['id'] for r in spec['payment_validity_goals']] != expected:
            raise ValueError('Payment-validity scope requires exactly the three user goals in order')
    rows = mappings(spec, payment_validity_only=args.payment_validity_only)
    files = sorted({s.split('::')[0] for r in rows for s in r['handlers'] + r['context']})
    texts, hashes = {}, {}
    for file in files:
        raw = (upstream / file).read_bytes()
        if hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() != blobs[file]:
            raise ValueError('Source differs from pinned Git blob: ' + file)
        texts[file] = raw.decode()
        hashes[file] = hashlib.sha256(raw).hexdigest()
    ast = json.loads(subprocess.check_output(
        ['node', '-e', AST_JS, str(BASE.parent / 'releases/tools/node_modules/typescript')],
        input=json.dumps(dict(root=str(upstream), files=files)).encode()))
    index = {f['selector']: dict(f, file=a['file']) for a in ast for f in a['functions']}
    for row in rows:
        for s in row['handlers'] + row['context']:
            if s not in index:
                raise ValueError('Unknown explicit selector: ' + s)
    graph, unresolved = {}, {}
    for selector, f in index.items():
        edges, gaps = set(), []
        for call in f['calls']:
            candidates = [s for s, v in index.items() if v['file'] == f['file'] and v['qualified'] == call['local_identifier']]
            if len(candidates) == 1:
                edges.add(candidates[0])
            else:
                gaps.append(call)
        graph[selector], unresolved[selector] = sorted(edges), gaps
    out.mkdir(parents=True)
    (out / 'slices').mkdir()
    (out / 'source-context').mkdir()

    def save(name, value):
        (out / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

    reports = []
    with sqlite3.connect(out / 'contexts.db') as db:
        db.execute('CREATE TABLE rule_code_snippet (rule_desc TEXT PRIMARY KEY, code_snippet TEXT, call_graph TEXT, llm_response TEXT)')
        for row in rows:
            seen, todo = set(), list(row['handlers'] + row['context'])
            while todo:
                s = todo.pop()
                if s not in seen:
                    seen.add(s)
                    todo.extend(graph[s])
            snippets = []
            locations = []
            for s in sorted(seen):
                f = index[s]
                code = '\n'.join(texts[f['file']].splitlines()[f['start']-1:f['end']])
                snippets.append('// ' + s + ':' + str(f['start']) + '-' + str(f['end']) + '\n' + code)
                locations.append({k: f[k] for k in ['selector', 'file', 'start', 'end']})
            snippet = '\n\n'.join(snippets) + '\n'
            (out / 'slices' / (row['id'] + '.ts.txt')).write_text(snippet)
            cg = {s: graph[s] for s in sorted(seen)}
            db.execute('INSERT INTO rule_code_snippet VALUES (?, ?, ?, NULL)', (row['rule'], snippet, json.dumps(cg)))
            report = dict(rule_id=row['id'], status='source_context_only_unreviewed',
                          handlers=row['handlers'], explicit_context=row['context'], functions=locations,
                          call_graph=cg, unresolved_calls={s: unresolved[s] for s in sorted(seen) if unresolved[s]},
                          full_source_context_files=sorted({index[s]['file'] for s in seen}),
                          snippet_file='slices/' + row['id'] + '.ts.txt', limits=row['limits'])
            save('slices/' + row['id'] + '.json', report)
            reports.append(dict(id=row['id'], functions=len(seen), unresolved_call_occurrences=sum(len(v) for v in report['unresolved_calls'].values()), status=report['status']))
    for file in files:
        dest = out / 'source-context' / file
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(texts[file])
    save('rules.json', rows)
    save('decisions.json', {r['id']: dict(handlers=r['handlers'], context=r['context']) for r in rows})
    save('static-index.json', ast)
    save('user-security-spec.json', spec)
    save('manifest.json', dict(commit=PIN, upstream=str(upstream), input_sha256=hashlib.sha256(spec_path.read_bytes()).hexdigest(),
                              source_spec_path=str(spec_path),
                              analysis_scope='payment_validity_only' if args.payment_validity_only else 'legacy_expanded_scope',
                              source_sha256=hashes, git_blob_identity_verified_for_selected_files=True,
                              method='explicit handlers/context plus unambiguous same-file function-call closure; whole-function preservation',
                              limits=['Not a dataflow, alias or control-dependence slice.', 'Imports, types, constants and module state are preserved in separate full-source context copies.', 'Imports/methods/dynamic calls are unresolved unless manually selected as context.', 'Nested callback calls are retained as conservative lexical occurrences, not proven runtime edges.', 'No semantic judgment, model call, target execution or formal proof.'],
                              rules=len(rows), source_files=len(files), reports=reports))
    # Verify the produced interface and exact line extraction without executing target code.
    with sqlite3.connect('file:' + str(out / 'contexts.db') + '?mode=ro', uri=True) as db:
        assert db.execute('SELECT count(*), sum(llm_response IS NULL) FROM rule_code_snippet').fetchone() == (len(rows), len(rows))
    for row in rows:
        report = json.loads((out / 'slices' / (row['id'] + '.json')).read_text())
        assert set(row['handlers']) <= {f['selector'] for f in report['functions']}
    save('validation.json', dict(json_parse=True, selectors_resolved=True, selected_source_blob_checks=True,
                                 database_rows=len(rows), model_results_null=True, target_code_executed=False))
    print(json.dumps(dict(output=str(out), rules=len(rows), files=len(files), reports=reports), indent=2))


if __name__ == '__main__':
    main()
