"""One bounded DeepSeek API review of a prepared user-spec slice; no dsh.

No network or credential access until --allow-paid and budget checks pass.
No automatic retries, seed generation, target execution, or dynamic validation.
"""
import argparse
import datetime
import getpass
import hashlib
import json
import math
from pathlib import Path
import sys
import urllib.error
import urllib.request
import warnings

from deepseek_harness_user_spec import BASE, PIN, SYSTEM, load_prepared, save, check_response

# Peak/cache-miss accounting rates checked against official pricing on 2026-11-13.
# Conservative local admission estimate, not a provider-enforced billing limit.
INPUT_RATE = 0.30
OUTPUT_RATE = 1.20
ENDPOINT = 'https://api.deepseek.com/v1/chat/completions'


def prepare_request(bundle, max_tokens):
    return dict(model='deepseek-flash', thinking=dict(type='disabled'),
                max_tokens=max_tokens, response_format=dict(type='json_object'),
                messages=[dict(role='system', content=bundle.get('review_instructions', SYSTEM)),
                          dict(role='user', content=json.dumps(bundle, ensure_ascii=False, separators=(',', ':')))])


def reservation(body, max_tokens):
    # UTF-8 request bytes + overhead intentionally overestimate input tokens.
    # Rates and tokenization can change; usage is checked after the response.
    return ((len(body) + 8192) * INPUT_RATE + max_tokens * OUTPUT_RATE) / 1_000_000


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--prepared', type=Path, default=BASE / 'deepseek-user-spec-inputs')
    p.add_argument('--rule', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--allow-paid', action='store_true')
    p.add_argument('--budget-usd', type=float, required=True,
                   help='local admission cap using documented peak rates; not a provider billing guarantee')
    p.add_argument('--max-output-tokens', type=int, default=6000)
    p.add_argument('--timeout-seconds', type=int, default=180)
    p.add_argument('--key-stdin', action='store_true',
                   help='read key from stdin instead of a hidden terminal prompt; never pass it as an argument')
    p.add_argument('--prepare-only', action='store_true', help='save request and estimate without reading a key or network')
    a = p.parse_args()
    out = a.output.resolve()
    if out.exists():
        p.error('Output already exists; select a new directory. No overwrite or resume.')
    if not math.isfinite(a.budget_usd) or a.budget_usd <= 0:
        p.error('budget-usd must be finite and positive')
    if not 256 <= a.max_output_tokens <= 16000 or not 1 <= a.timeout_seconds <= 600:
        p.error('max-output-tokens must be 256..16000; timeout-seconds must be 1..600')
    if not a.prepare_only and not a.allow_paid:
        p.error('API execution requires --allow-paid; no key read or request sent.')
    prepared = a.prepared.resolve()
    bundle, _ = load_prepared(prepared, a.rule)
    payload = prepare_request(bundle, a.max_output_tokens)
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    if len(body) > 2_000_000:
        p.error('Request exceeds local 2 MB limit; no request sent.')
    reserved = reservation(body, a.max_output_tokens)
    if reserved > a.budget_usd:
        p.error('Conservative request estimate exceeds budget; no key read or request sent. Estimated USD %.6f' % reserved)
    out.mkdir(parents=True)
    save(out / 'request.json', payload)
    ledger = dict(provider='DeepSeek', transport='direct Chat Completions API',
                  model=payload['model'], rule_id=a.rule, target=PIN,
                  created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  input_sha256=hashlib.sha256((prepared / 'inputs' / (a.rule + '.json')).read_bytes()).hexdigest(),
                  request_sha256=hashlib.sha256(body).hexdigest(), request_bytes=len(body),
                  request_cap=1, automatic_retries=0, max_output_tokens=a.max_output_tokens,
                  budget_usd=a.budget_usd, conservative_reservation_usd=reserved,
                  accounting_rates_usd_per_million=dict(input_cache_miss=INPUT_RATE, output=OUTPUT_RATE),
                  pricing_reference='https://api-docs.deepseek.com/quick_start/pricing/',
                  billing_limit='Local request admission only; rates/tokenization and actual charges require provider confirmation.',
                  credential_persisted=False, hidden_reasoning_persisted=False, status='prepared')
    save(out / 'usage.json', ledger)
    if a.prepare_only:
        print(json.dumps(dict(output=str(out), status='prepared_only', model_calls=0,
                              conservative_reservation_usd=reserved)))
        return
    try:
        if a.key_stdin:
            key = sys.stdin.readline().strip()
        else:
            # Never fall back to echoed input when no controlling terminal exists.
            with open('/dev/tty', 'r+') as terminal:
                with warnings.catch_warnings():
                    warnings.simplefilter('error', getpass.GetPassWarning)
                    key = getpass.getpass('ProtocolGuard DeepSeek API key: ', stream=terminal).strip()
        if not key:
            raise ValueError('Dedicated ProtocolGuard key required; no request sent')
    except (EOFError, OSError, getpass.GetPassWarning):
        ledger['status'] = 'credential_input_unavailable_no_request'
        save(out / 'usage.json', ledger)
        raise ValueError('Hidden terminal input unavailable; use --key-stdin from a secure source') from None
    ledger['status'] = 'requesting'
    save(out / 'usage.json', ledger)
    request = urllib.request.Request(ENDPOINT, data=body,
        headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=a.timeout_seconds) as response:
            answer = json.load(response)
    except urllib.error.HTTPError as error:
        ledger.update(status='http_error', http_status=error.code,
                      reserved_on_failure_usd=reserved, actual_charge='unknown')
        save(out / 'usage.json', ledger)
        # Never read or print provider error bodies or request headers.
        raise ValueError('DeepSeek HTTP %s; no retry' % error.code) from None
    except Exception:
        ledger.update(status='transport_or_response_error', reserved_on_failure_usd=reserved,
                      actual_charge='unknown')
        save(out / 'usage.json', ledger)
        raise ValueError('API transport/response failure; no retry') from None
    finally:
        key = None
        request = None
    if not isinstance(answer, dict):
        ledger['status'] = 'invalid_response_shape'
        save(out / 'usage.json', ledger)
        raise ValueError('Invalid response shape; no retry')
    usage = answer.get('usage', {})
    # Persist whitelisted accounting fields only, not arbitrary response metadata.
    if not isinstance(usage, dict):
        usage = {}
    counts = {k: usage.get(k) for k in ['prompt_tokens', 'completion_tokens', 'total_tokens']
              if type(usage.get(k)) is int and usage[k] >= 0}
    estimate = ((counts['prompt_tokens'] * INPUT_RATE + counts['completion_tokens'] * OUTPUT_RATE) / 1_000_000
                if 'prompt_tokens' in counts and 'completion_tokens' in counts else None)
    ledger.update(status='response_received', usage=counts, estimated_peak_cost_usd=estimate)
    save(out / 'usage.json', ledger)
    choices = answer.get('choices')
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        ledger['status'] = 'invalid_response_shape'
        save(out / 'usage.json', ledger)
        raise ValueError('Invalid response shape; no retry')
    choice = choices[0]
    finish = choice.get('finish_reason')
    message = choice.get('message')
    content = message.get('content') if isinstance(message, dict) else None
    ledger['finish_reason'] = finish
    if not isinstance(content, str):
        ledger['status'] = 'missing_text_response'
        save(out / 'usage.json', ledger)
        raise ValueError('Missing text response; no retry')
    (out / 'response.txt').write_text(content)
    if finish != 'stop':
        ledger['status'] = 'non_stop_response_no_retry'
        save(out / 'usage.json', ledger)
        raise ValueError('Response incomplete or stopped by provider; no retry or workaround')
    try:
        check_response(prepared, a.rule, out / 'response.txt', out,
                       provenance='user-invoked direct DeepSeek Chat Completions API')
    except ValueError:
        ledger['status'] = 'schema_or_evidence_validation_failed'
        save(out / 'usage.json', ledger)
        raise
    ledger['status'] = 'grounded_model_judgment_unverified'
    save(out / 'usage.json', ledger)
    print(json.dumps(dict(output=str(out), status=ledger['status'], estimated_peak_cost_usd=estimate)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        print('Stopped: ' + (str(error) if isinstance(error, ValueError) else type(error).__name__), file=sys.stderr)
        sys.exit(1)
