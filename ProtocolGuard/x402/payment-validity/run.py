"""Single manual entry point for the corrected three-goal analysis.

status: read existing artifacts only.
review: opt-in paid inference; each selected goal is one request.
dynamic: opt-in local HTTP/mock-ledger validation of the same run's reviews.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SECURITY = ROOT.parent / 'security'
GOALS = ['PAYER_AUTHORIZATION', 'PAYMENT_BINDING', 'REPLAY_RESISTANCE']


def status(run):
    records = {}
    for goal in GOALS:
        folder = run / 'reviews' / goal
        if (folder / 'review.json').exists():
            records[goal] = 'review_present'
        elif (folder / 'usage.json').exists():
            value = json.loads((folder / 'usage.json').read_text())
            records[goal] = value.get('status', 'attempt_recorded')
        else:
            records[goal] = 'not_run'
    dynamic = run / 'dynamic/results.json'
    return dict(run=str(run), scope=GOALS, reviews=records,
                dynamic=json.loads(dynamic.read_text()).get('status') if dynamic.exists() else 'not_run',
                traces=len(list((run / 'dynamic/traces').glob('*.json'))))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage', choices=['status', 'review', 'dynamic'])
    p.add_argument('--run-id', default='run-001')
    p.add_argument('--goal', choices=['all', *GOALS], default='all')
    p.add_argument('--key-file', type=Path)
    p.add_argument('--allow-paid', action='store_true')
    p.add_argument('--execute', action='store_true')
    a = p.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', a.run_id):
        p.error('run-id must be a simple directory name without path separators')
    run = ROOT / 'runs' / a.run_id
    if a.stage == 'status':
        print(json.dumps(status(run), ensure_ascii=False, indent=2))
        return
    if a.stage == 'review':
        if not a.allow_paid or not a.key_file:
            p.error('review requires --allow-paid and --key-file; no request sent')
        goals = GOALS if a.goal == 'all' else [a.goal]
        # Reject an accidental repeat of an existing selected goal before any
        # new paid request in this invocation; missing goals can be selected.
        if any((run / 'reviews' / goal).exists() for goal in goals):
            p.error('A selected review output exists. Select a missing --goal or a new --run-id; no retry.')
        for goal in goals:
            subprocess.run([sys.executable, str(SECURITY / 'codex_api_user_spec.py'),
                '--prepared', str(ROOT / 'prepared'), '--rule', goal,
                '--model', 'gpt-6.1-sol', '--reasoning-effort', 'low',
                '--key-file', str(a.key_file.resolve()),
                '--output', str(run / 'reviews' / goal), '--allow-paid'], check=True)
        return
    if not a.execute:
        p.error('dynamic requires --execute; target code has not run')
    subprocess.run([sys.executable, str(SECURITY / 'validate_payment_validity.py'),
        '--prepared', str(ROOT / 'prepared'), '--review-root', str(run / 'reviews'),
        '--output', str(run / 'dynamic'), '--execute'], check=True)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError):
        print('Stopped; inspect existing run artifacts. No automatic retry.', file=sys.stderr)
        sys.exit(1)
