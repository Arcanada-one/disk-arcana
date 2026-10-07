#!/usr/bin/env python3
# Canonical merge-gate implementation; public diagnostic annotations.
import argparse
import json
import subprocess
import sys
from datetime import datetime
NOT_STARTED_MARKERS = ('was not started', 'not started because')

def _ts(s):
    if not s:
        return None
    return datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ')

def classify(job, annotations=None):
    steps = job.get('steps') or []
    runner = (job.get('runner_name') or '').strip()
    conclusion = job.get('conclusion')
    status = job.get('status')
    start, end = (_ts(job.get('started_at')), _ts(job.get('completed_at')))
    duration = int((end - start).total_seconds()) if start and end else None
    reason = ''
    for a in annotations or []:
        msg = a.get('message') or ''
        if any((m in msg for m in NOT_STARTED_MARKERS)):
            reason = msg.split('. ')[0]
            break
    if status != 'completed':
        verdict = 'in_progress'
    elif conclusion == 'failure' and (not runner) and (len(steps) == 0):
        verdict = 'not_started'
        reason = reason or 'no runner, no steps (refusal message not read)'
    elif conclusion == 'failure' or conclusion == 'timed_out':
        verdict = 'failure'
    elif conclusion in ('success', 'skipped', 'neutral'):
        verdict = conclusion
    elif conclusion == 'cancelled':
        verdict = 'cancelled'
    else:
        verdict = 'unknown'
    return {'name': job.get('name'), 'verdict': verdict, 'conclusion': conclusion, 'runner_name': runner, 'steps': len(steps), 'duration_s': duration, 'reason': reason}

def exit_code(rows):
    if not rows:
        return 3
    verdicts = {r['verdict'] for r in rows}
    if verdicts & {'not_started', 'in_progress', 'unknown', 'cancelled'}:
        return 3
    if 'failure' in verdicts:
        return 1
    return 0

def gh(path):
    r = subprocess.run(['gh', 'api', path], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f'gh api {path}: rc={r.returncode} {r.stderr.strip()[:200]}')
    return json.loads(r.stdout)

def render(rows, as_json):
    empty_reason = 'No jobs returned — not measured; workflow startup cause is unknown.'
    if as_json:
        result = {'schema': 'JobStartVerdict/v1', 'jobs': rows, 'exit': exit_code(rows)}
        if not rows:
            result.update(verdict='unknown', reason=empty_reason)
        print(json.dumps(result, indent=1))
        return
    print('| job | verdict | conclusion | runner | steps | duration_s | reason |')
    print('|---|---|---|---|---|---|---|')
    for r in rows:
        print(f'| {r['name']} | {r['verdict']} | {r['conclusion']} | {r['runner_name'] or '-'} | {r['steps']} | {r['duration_s']} | {r['reason']} |')
    n = sum((r['verdict'] == 'not_started' for r in rows))
    if not rows:
        print(f'\n{empty_reason}')
    if n:
        print(f'\n{n} job(s) NOT STARTED — not measured; this is not a verdict on the change.')

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    sub = p.add_subparsers(dest='cmd', required=True)
    live = sub.add_parser('run')
    live.add_argument('--repo', required=True)
    live.add_argument('--run-id', required=True)
    live.add_argument('--json', action='store_true')
    off = sub.add_parser('jobs')
    off.add_argument('--jobs-json', required=True)
    off.add_argument('--annotations', action='append', default=[], metavar='JOB_ID=FILE')
    off.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    try:
        if a.cmd == 'run':
            jobs = gh(f'repos/{a.repo}/actions/runs/{a.run_id}/jobs?per_page=100')['jobs']
            rows = []
            for j in jobs:
                ann = None
                if j.get('conclusion') == 'failure' and (not (j.get('runner_name') or '').strip()):
                    try:
                        ann = gh(f'repos/{a.repo}/check-runs/{j['id']}/annotations')
                    except RuntimeError:
                        ann = None
                rows.append(classify(j, ann))
        else:
            with open(a.jobs_json) as f:
                jobs = json.load(f)['jobs']
            ann_by_id = {}
            for spec in a.annotations:
                jid, _, path = spec.partition('=')
                with open(path) as f:
                    ann_by_id[int(jid)] = json.load(f)
            rows = [classify(j, ann_by_id.get(j.get('id'))) for j in jobs]
    except (OSError, ValueError, KeyError, RuntimeError) as e:
        print(f'job-start-verdict: {e}', file=sys.stderr)
        return 2
    render(rows, a.json)
    return exit_code(rows)
if __name__ == '__main__':
    sys.exit(main())
