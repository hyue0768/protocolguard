"""Manual, one-request Responses API review of a pinned user-spec slice.

Preparation never reads credentials or accesses the network. Real inference is
opt-in with --allow-paid. Credentials stay in their existing external file.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

from deepseek_harness_user_spec import BASE, PIN, SYSTEM, check_response, load_prepared, save


def endpoint_for(base):
    u = urllib.parse.urlsplit(base)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError('API base URL must be HTTPS without credentials, query or fragment')
    path = u.path.rstrip('/')
    if not path.endswith('/responses'):
        path += '/responses'
    return urllib.parse.urlunsplit((u.scheme, u.netloc, path, '', ''))


def json_mode_input(value):
    # The API requires the word 'json' in input itself, even when instructions
    # already specify JSON. Do not depend on incidental words in source/specs.
    return 'Return a valid json object only.\n\n' + json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def request_body(bundle, model, max_tokens, effort=None):
    value = dict(model=model, instructions=bundle.get('review_instructions', SYSTEM),
                 input=json_mode_input(bundle),
                 max_output_tokens=max_tokens, store=False, tools=[], stream=False,
                 text=dict(format=dict(type='json_object')))
    if effort:
        value['reasoning'] = dict(effort=effort)
    return value


def read_key(path):
    value = path.read_text().strip()
    # Also accept a standard API-key JSON file, without copying other contents.
    if value.startswith('{'):
        try:
            data = json.loads(value)
            value = data.get('OPENAI_API_KEY') or data.get('api_key')
        except (ValueError, AttributeError):
            raise ValueError('Credential file has unsupported JSON structure') from None
    if not isinstance(value, str) or not value or any(c.isspace() for c in value):
        raise ValueError('Credential file must contain one token or an API-key JSON object')
    return value


def final_text(answer):
    if not isinstance(answer, dict):
        raise ValueError('Provider response is not a JSON object')
    if answer.get('status') != 'completed':
        raise ValueError('Provider did not complete the response; no retry or workaround')
    parts = []
    output = answer.get('output')
    if not isinstance(output, list):
        raise ValueError('Missing Responses API output array')
    for item in output:
        if not isinstance(item, dict) or item.get('type') != 'message' or item.get('role') != 'assistant':
            continue
        for content in item.get('content', []):
            if not isinstance(content, dict):
                continue
            if content.get('type') == 'refusal':
                raise ValueError('Provider refusal; no retry or workaround')
            if content.get('type') == 'output_text' and isinstance(content.get('text'), str):
                parts.append(content['text'])
    if not parts:
        raise ValueError('No final assistant text; no retry')
    return ''.join(parts)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the Authorization header to a redirected host.
        return None


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared', type=Path, default=BASE.parent / 'payment-validity/prepared')
    p.add_argument('--rule', required=True)
    p.add_argument('--model', required=True, help='exact model ID provided by your API service')
    p.add_argument('--api-base-url', default='https://api.openai.com/v1')
    p.add_argument('--key-file', type=Path, help='external credential file; read only for an explicitly enabled request')
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--max-output-tokens', type=int, default=12000)
    p.add_argument('--reasoning-effort', choices=['none', 'minimal', 'low', 'medium', 'high', 'xhigh'])
    p.add_argument('--timeout-seconds', type=int, default=300)
    p.add_argument('--prepare-only', action='store_true')
    p.add_argument('--allow-paid', action='store_true')
    a = p.parse_args()
    if not a.model.strip() or any(x.isspace() for x in a.model):
        p.error('model must be an exact nonempty ID')
    if not 256 <= a.max_output_tokens <= 32000 or not 1 <= a.timeout_seconds <= 600:
        p.error('Output token limit must be 256..32000; timeout must be 1..600 seconds')
    out = a.output.resolve()
    if out.exists():
        p.error('Output already exists; no overwrite or resume')
    if not a.prepare_only and not a.allow_paid:
        p.error('Real API execution requires --allow-paid; no key read or request sent')
    if not a.prepare_only and not a.key_file:
        p.error('Real execution requires --key-file')
    endpoint = endpoint_for(a.api_base_url)
    prepared = a.prepared.resolve()
    bundle, _ = load_prepared(prepared, a.rule)
    payload = request_body(bundle, a.model, a.max_output_tokens, a.reasoning_effort)
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    if len(body) > 2_000_000:
        p.error('Request exceeds local 2 MB limit; no request sent')
    # Read key only after the explicit execution gate and request checks.
    key = None
    if not a.prepare_only:
        try:
            key = read_key(a.key_file.resolve())
        except OSError:
            raise ValueError('Credential file unavailable; no request sent') from None
    out.mkdir(parents=True)
    save(out / 'request.json', payload)
    ledger = dict(transport='Responses API', rule_id=a.rule, target=PIN,
                  requested_model=a.model, endpoint=endpoint,
                  created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  input_sha256=hashlib.sha256((prepared / 'inputs' / (a.rule + '.json')).read_bytes()).hexdigest(),
                  request_sha256=hashlib.sha256(body).hexdigest(), request_bytes=len(body),
                  request_cap=1, automatic_retries=0, max_output_tokens=a.max_output_tokens,
                  store_requested=False, tools_requested=[],
                  credential_persisted=False, hidden_reasoning_persisted=False,
                  provider_billing_cap_enforced=False,
                  status='prepared_only' if a.prepare_only else 'requesting')
    save(out / 'usage.json', ledger)
    if a.prepare_only:
        print(json.dumps(dict(output=str(out), status='prepared_only', model_calls=0,
                              credential_read=False, request_bytes=len(body))))
        return
    request = urllib.request.Request(endpoint, data=body,
        headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}, method='POST')
    try:
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(request, timeout=a.timeout_seconds) as response:
            answer = json.load(response)
    except urllib.error.HTTPError as error:
        ledger.update(status='http_error', http_status=error.code, actual_charge='unknown')
        save(out / 'usage.json', ledger)
        raise ValueError('API HTTP %s; error body suppressed; no retry' % error.code) from None
    except Exception:
        ledger.update(status='transport_or_response_error', actual_charge='unknown')
        save(out / 'usage.json', ledger)
        raise ValueError('API transport/response failure; no retry') from None
    finally:
        key = None
        request = None
    usage = answer.get('usage', {}) if isinstance(answer, dict) else {}
    if not isinstance(usage, dict):
        usage = {}
    ledger['usage'] = {k: usage[k] for k in ['input_tokens', 'output_tokens', 'total_tokens']
                       if type(usage.get(k)) is int and usage[k] >= 0}
    if isinstance(answer, dict):
        ledger['provider_status'] = answer.get('status')
        # Do not persist raw reasoning, headers, provider errors, or tool output.
    try:
        text = final_text(answer)
        (out / 'response.txt').write_text(text)
        check_response(prepared, a.rule, out / 'response.txt', out,
                       provenance='user-invoked Responses API; requested model ' + a.model)
    except ValueError:
        ledger['status'] = 'incomplete_refused_or_validation_failed_no_retry'
        save(out / 'usage.json', ledger)
        raise
    ledger['status'] = 'grounded_model_judgment_unverified'
    save(out / 'usage.json', ledger)
    print(json.dumps(dict(output=str(out), status=ledger['status'])))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print('Stopped: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
