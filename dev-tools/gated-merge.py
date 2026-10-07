#!/usr/bin/env python3
# Canonical merge-gate implementation; public diagnostic annotations.
import argparse
import datetime as dt
import functools
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
OK = {'SUCCESS'}
TOLERATED = {'NEUTRAL', 'SKIPPED'}
HERE = os.path.dirname(os.path.abspath(__file__))
RETRYABLE = {'CANCELLED', 'TIMED_OUT', 'STALE'}
EXIT = {'merits': 1, 'not_started': 3, 'cancelled': 4, 'pending': 5}
ORDER = ['merits', 'not_started', 'cancelled', 'pending']
ACTION = {'merits': 'fix the change; re-running will not help', 'not_started': 'not measured — GitHub did not start the job (see dev-tools/ci/job-start-verdict.py); restore the runner/billing, then re-run', 'cancelled': 're-run the job and wait (or run the gate with --rerun-cancelled)', 'pending': 'wait for the checks to finish, then run the gate again'}
REASON_ACTION = {'PR_NOT_FOUND': 'check --repo and --pr; there is nothing to merge', 'PR_NOT_OPEN': 'the PR is closed or merged; there is nothing to merge', 'PR_IS_DRAFT': 'mark the PR ready for review, then run the gate again', 'BASE_NOT_DEFAULT': 'retarget the PR to the default branch (or merge it by its own lane)', 'MERGE_CONFLICT': 'rebase the branch on the default branch and push; CI then runs on the new head', 'MERGE_STATE_NOT_MEASURED': 'GitHub has not computed mergeability yet (UNKNOWN): the gate re-read it and it stayed unmeasured; wait a few seconds and run the gate again — an unmeasured state is never a merge', 'HEAD_MOVED': 'the PR has a new head: review it, then run the gate again with --expect-sha <new head>', 'NO_CHECKS': 'no workflow ran on this head: push or re-trigger CI, then run the gate again', 'STALE_BASE': 'update the branch from the default branch (merge or rebase), let CI run on the new head, gate again', 'REQUIRED_NOT_STARTED': 'a required workflow did not run on this head: re-trigger it (or fix its trigger)'}
ADMISSION_WORKFLOW = '^graph-admission.*\\.ya?ml$'
ADMISSION_CHECK = 'graph-admission / graph-admission'
SHA = re.compile('^(?:[0-9a-f]{40}|[0-9a-f]{64})$')

def action_for(cause):
    head = cause['reason'].split(':', 1)[0]
    return REASON_ACTION.get(head) or ACTION[cause['class']]

def full_sha(s):
    s = (s or '').strip().lower()
    return s if SHA.match(s) else None

@functools.lru_cache(maxsize=None)
def _jsv():
    spec = importlib.util.spec_from_file_location('job_start_verdict', os.path.join(HERE, 'ci', 'job-start-verdict.py'))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
Q = '\nquery($owner:String!,$name:String!,$n:Int!){\n  repository(owner:$owner,name:$name){\n    isPrivate\n    defaultBranchRef{ name target { oid } }\n    workflows: object(expression:"HEAD:.github/workflows"){ ... on Tree { entries { name } } }\n    pullRequest(number:$n){ number state isDraft baseRefName headRefOid mergeable mergeStateStatus\n      commits(last:1){ nodes{ commit{ oid\n        checkSuites(first:50){ nodes{ app{slug} status conclusion\n          checkRuns(first:50){ nodes{ name status conclusion completedAt startedAt databaseId } } } } } } } }\n  }\n}'

def load_policy(path, repo):
    pol = json.load(open(path))
    d = dict(pol.get('_default', {}))
    d.update(pol.get(repo, {}))
    return d

def admission_required(answer, policy):
    req = list(policy.get('required', []))
    r = answer.get('repository') or {}
    if 'workflows' not in r:
        return (req, 'not_read')
    names = [e.get('name') or '' for e in (r.get('workflows') or {}).get('entries') or []]
    pat = re.compile(policy.get('admission_workflow', ADMISSION_WORKFLOW))
    check = policy.get('admission_check', ADMISSION_CHECK)
    if any((pat.match(n) for n in names)) and check not in req:
        return (req + [check], 'workflow-on-default-branch')
    return (req, 'policy')

@functools.lru_cache(maxsize=1)
def _merge_impact():
    spec = importlib.util.spec_from_file_location('merge_impact', os.path.join(HERE, 'merge-impact.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def current_base(answer):
    branch = (answer.get('repository') or {}).get('defaultBranchRef') or {}
    return (branch.get('target') or {}).get('oid')

def stale_base(answer, policy, lanes):
    limit = policy.get('max_behind')
    if 'base_compare' not in answer:
        return (None, {'behind_by': None, 'note': 'not_read'})
    cmp_ = answer['base_compare']
    if not cmp_ or cmp_.get('error'):
        info = {'behind_by': None, 'note': (cmp_ or {}).get('error') or 'not_read'}
        return (f'STALE_BASE:not measured ({info['note'][:80]}) and the policy sets max_behind={limit}' if limit is not None else None, info)
    today = dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%d')
    pats = [re.compile(x['pattern']) for x in lanes if not x.get('expires') or x['expires'] >= today]
    missed = [m for m in cmp_.get('missed', []) if not any((pt.search(m) for pt in pats))]
    real = len(missed) + max(0, cmp_['behind_by'] - len(cmp_.get('missed', [])))
    info = {'behind_by': cmp_['behind_by'], 'behind_not_lane': real, 'missed_not_lane': missed[:20]}
    if limit is not None and real > limit:
        spec = policy.get('disjoint_merge') or {}
        proof = answer.get('disjoint_merge_proof')
        head = ((answer.get('repository') or {}).get('pullRequest') or {}).get('headRefOid')
        if spec.get('enabled') is True and _merge_impact().admissible(proof, head, current_base(answer), spec.get('decision_ref')):
            info.update(disjoint_merge_proof=proof, stale_base_disposition='graph_disjoint_clean_merge')
            return (None, info)
        if proof is not None:
            info.update(disjoint_merge_proof=proof, stale_base_disposition='proof_refused')
        return (f'STALE_BASE:head is {real} non-lane commit(s) behind the default branch (max_behind={limit})', info)
    return (None, info)

def classify_check(c, job):
    st, co = (c['status'], c['conclusion'])
    if st != 'COMPLETED':
        return ('pending', '')
    if co in RETRYABLE:
        runner = (job or {}).get('runner_name') or ''
        return ('cancelled', f'runner={runner or '-'} steps={(len((job or {}).get('steps') or []) if job else '?')}')
    if co == 'STARTUP_FAILURE':
        return ('not_started', 'STARTUP_FAILURE')
    if co == 'FAILURE' and job is not None:
        v = _jsv().classify(job)
        if v['verdict'] == 'not_started':
            return ('not_started', v['reason'])
        return ('merits', f'ran on {v['runner_name'] or '-'}, {v['steps']} steps')
    if co == 'FAILURE':
        return ('merits', 'job record not read — a FAILURE stays on merits without evidence otherwise')
    return ('merits', '')

def mergeability_unmeasured(pr):
    return pr.get('mergeable') in (None, 'UNKNOWN') or pr.get('mergeStateStatus') == 'UNKNOWN'

def reread_until_measured(read, retries=3, delay=2.0, sleep=time.sleep):
    reads = 1
    ans = read()
    while reads <= retries:
        pr = (ans.get('repository') or {}).get('pullRequest') or {}
        if pr.get('state') != 'OPEN' or not mergeability_unmeasured(pr):
            break
        sleep(delay)
        ans = read()
        reads += 1
    return (ans, reads)

def judge(answer, policy, expect_sha=None, jobs=None, lanes=()):
    jobs = jobs or {}
    required, _ = admission_required(answer, policy)
    r = answer['repository']
    pr = r['pullRequest']
    reasons = []
    if pr is None:
        return ('REFUSE', ['PR_NOT_FOUND'], {}, [{'class': 'merits', 'reason': 'PR_NOT_FOUND'}])
    if pr['state'] != 'OPEN':
        reasons.append(f'PR_NOT_OPEN:{pr['state']}')
    if pr['isDraft']:
        reasons.append('PR_IS_DRAFT')
    if r['defaultBranchRef'] and pr['baseRefName'] != r['defaultBranchRef']['name'] and policy.get('default_branch_only', True):
        reasons.append(f'BASE_NOT_DEFAULT:{pr['baseRefName']}')
    if pr.get('mergeable') == 'CONFLICTING' or pr.get('mergeStateStatus') == 'DIRTY':
        reasons.append('MERGE_CONFLICT')
    elif pr['state'] == 'OPEN' and mergeability_unmeasured(pr):
        reasons.append(f'MERGE_STATE_NOT_MEASURED:mergeable={pr.get('mergeable')},mergeStateStatus={pr.get('mergeStateStatus')}')
    stale, _ = stale_base(answer, policy, lanes)
    if stale:
        reasons.append(stale)
    head = pr['headRefOid']
    if expect_sha and full_sha(expect_sha) != (head or '').lower():
        reasons.append(f'HEAD_MOVED:expected={expect_sha} head={head}')
    nodes = pr['commits']['nodes']
    runs = []
    if nodes and nodes[0]['commit']['oid'] == head:
        for s in nodes[0]['commit']['checkSuites']['nodes']:
            slug = (s.get('app') or {}).get('slug')
            if policy.get('apps') and slug not in policy['apps']:
                continue
            for c in s['checkRuns']['nodes']:
                runs.append(dict(c, app=slug))
    latest = {}
    for c in runs:
        k = c['name']
        key = (c.get('completedAt') or '9999', c.get('startedAt') or '', c.get('databaseId') or 0)
        if c.get('status') != 'COMPLETED':
            key = ('9999',) + key[1:]
        if k not in latest or key >= latest[k][0]:
            latest[k] = (key, c)
    checks = {k: {'status': v[1]['status'], 'conclusion': v[1]['conclusion'], 'app': v[1]['app'], 'job_id': v[1].get('databaseId')} for k, v in sorted(latest.items())}
    causes = [{'class': 'pending' if x.startswith('MERGE_STATE_NOT_MEASURED') else 'merits', 'reason': x} for x in reasons]

    def red(reason, name):
        c = checks[name]
        cls, note = classify_check(c, jobs.get(c['job_id']))
        reasons.append(reason)
        causes.append({'class': cls, 'reason': reason, 'check': name, 'job_id': c['job_id'], 'note': note})
    if not checks:
        reasons.append('NO_CHECKS: the head commit carries no check run — CI never started, or never ran')
        causes.append({'class': 'merits', 'reason': reasons[-1]})
    for req in required:
        c = checks.get(req)
        if c is None:
            reasons.append(f'REQUIRED_NOT_STARTED:{req}')
            causes.append({'class': 'merits', 'reason': reasons[-1], 'check': req})
        elif c['status'] != 'COMPLETED':
            red(f'REQUIRED_PENDING:{req}={c['status']}', req)
        elif c['conclusion'] not in OK and (not (c['conclusion'] in TOLERATED and policy.get('tolerate_neutral_required'))):
            if c['conclusion'] in TOLERATED:
                reasons.append(f'REQUIRED_RED:{req}={c['conclusion']}')
                causes.append({'class': 'merits', 'reason': reasons[-1], 'check': req})
            else:
                red(f'REQUIRED_RED:{req}={c['conclusion']}', req)
    for n, c in checks.items():
        if n in required or n in policy.get('ignore', []):
            continue
        if c['status'] != 'COMPLETED':
            red(f'PENDING:{n}={c['status']}', n)
        elif c['conclusion'] not in OK | TOLERATED:
            red(f'RED:{n}={c['conclusion']}', n)
    return ('REFUSE' if reasons else 'ADMIT', reasons, checks, causes)

def refusal_class(causes):
    present = {c['class'] for c in causes}
    return next((k for k in ORDER if k in present), None)

def gh(args):
    p = subprocess.run(['gh', 'api'] + args, capture_output=True, text=True)
    return (p.returncode, p.stdout, p.stderr)

def read_answer(owner, name, n):
    rc, out, err = gh(['graphql', '-f', 'query=' + Q, '-f', f'owner={owner}', '-f', f'name={name}', '-F', f'n={n}'])
    d = json.loads(out)
    if rc != 0 or d.get('errors'):
        raise ValueError((err or json.dumps(d.get('errors')))[:300])
    return d['data']

def read_compare(repo, head, base):
    try:
        rc, out, err = gh([f'repos/{repo}/compare/{head}...{base}'])
        if rc != 0:
            return {'error': (err or out).strip()[:200]}
        c = json.loads(out)
        return {'behind_by': c['ahead_by'], 'missed': [x['commit']['message'].split('\n', 1)[0] for x in c.get('commits', [])], 'files': compare_files(c)}
    except Exception as e:
        return {'error': str(e)[:200]}
COMPARE_FILE_CAP = 300

def compare_files(c):
    names = set()
    for f in c.get('files') or []:
        names.add(f['filename'])
        if f.get('previous_filename'):
            names.add(f['previous_filename'])
    return {'names': sorted(names), 'complete': len(c.get('files') or []) < COMPARE_FILE_CAP}

def read_pr_files(repo, base, head):
    try:
        rc, out, err = gh([f'repos/{repo}/compare/{base}...{head}'])
        if rc != 0:
            return {'error': (err or out).strip()[:200]}
        return compare_files(json.loads(out))
    except Exception as e:
        return {'error': str(e)[:200]}

def _under(path, prefixes):
    return any((path == x or (x.endswith('/') and path.startswith(x)) for x in prefixes))

def file_disjoint_shadow(pr_files, behind_files, spec):
    out = {'mode': 'shadow', 'rule': 'file-disjoint-docs-stale-base-v1', 'merged_result_executed': False}
    for label, f in (('PR', pr_files), ('INTERVENING', behind_files)):
        if not f or f.get('error'):
            return {**out, 'verdict': 'not_measured', 'reasons': [f'{label}_FILES_UNREAD:{((f or {}).get('error') or 'absent')[:80]}']}
        if not f.get('complete'):
            return {**out, 'verdict': 'not_measured', 'reasons': [f'{label}_FILES_TRUNCATED:{len(f['names'])}']}
    docs, glob = (spec.get('docs_prefixes', []), spec.get('global_prefixes', []))
    shared = spec.get('shared_state', [])
    reasons = []
    reasons += [f'PR_NOT_DOCS_CLASS:{x}' for x in pr_files['names'] if not _under(x, docs)][:5]
    reasons += [f'INTERVENING_GLOBAL_INPUT:{x}' for x in behind_files['names'] if _under(x, glob)][:5]
    reasons += [f'INTERVENING_NOT_DOCS_CLASS:{x}' for x in behind_files['names'] if not _under(x, docs)][:5]
    both = set(pr_files['names']) & set(behind_files['names'])
    reasons += [f'OVERLAP:{x}' for x in sorted(both)][:5]
    reasons += [f'SHARED_STATE:{x}' for x in sorted(set(pr_files['names']) | set(behind_files['names'])) if _under(x, shared)][:5]
    return {**out, 'verdict': 'would_refuse' if reasons else 'would_admit', 'reasons': reasons, 'pr_files': len(pr_files['names']), 'intervening_files': len(behind_files['names'])}

def failing_ids(answer, policy):
    _, _, checks, _ = judge(answer, policy)
    return [c['job_id'] for c in checks.values() if c['status'] == 'COMPLETED' and c['conclusion'] not in OK | TOLERATED and c['job_id']]

def read_jobs(repo, ids, jobs_dir=None):
    jobs = {}
    for i in ids:
        try:
            if jobs_dir:
                f = os.path.join(jobs_dir, f'job-{i}.json')
                if os.path.exists(f):
                    jobs[i] = json.load(open(f))
                continue
            rc, out, _ = gh([f'repos/{repo}/actions/jobs/{i}'])
            if rc == 0:
                jobs[i] = json.loads(out)
        except (OSError, ValueError):
            pass
    return jobs

def rerun(repo, job_id):
    rc, out, err = gh(['-X', 'POST', f'repos/{repo}/actions/jobs/{job_id}/rerun'])
    if rc == 0:
        return 'started'
    text = (out + ' ' + err).strip()
    if '403' in text and re.search('already running', text, re.I):
        return 'busy'
    return 'error:' + text[:200]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--repo', required=True, help='owner/name')
    ap.add_argument('--pr', type=int, required=True)
    ap.add_argument('--method', default='merge', choices=['merge', 'squash', 'rebase'])
    ap.add_argument('--policy', default=os.path.join(HERE, 'merge-gate-policy.json'))
    ap.add_argument('--expect-sha', help='refuse unless the PR head is exactly this SHA (full 40 hex; a prefix is refused, exit 2)')
    ap.add_argument('--dry-run', action='store_true', help='judge, never merge')
    ap.add_argument('--from-json', help='judge a saved GraphQL answer (implies --dry-run)')
    ap.add_argument('--jobs-dir', help='with --from-json: saved REST job records job-<id>.json')
    ap.add_argument('--repo-dir', help='existing receiving Git object database; never checked out or reset')
    ap.add_argument('--graph-repo', help='existing canonical Program Git object database for policy-pinned graph producer')
    ap.add_argument('--impact-workdir', help='owned durable directory for graph proof and producer source')
    ap.add_argument('--lanes', help='scheduled-lane commit patterns (default dev-tools/merge-gate-lanes.json)')
    ap.add_argument('--dump-answer', help='also save the raw GraphQL answer here (fixtures)')
    ap.add_argument('--receipt', help='write the MergeGateReceipt/v1 here as well as stdout')
    ap.add_argument('--rerun-cancelled', action='store_true', help='re-run each CANCELLED/TIMED_OUT job once and wait; never a red on merits')
    ap.add_argument('--rerun-wait', type=int, default=1800, help='seconds to wait for re-runs (max 3600)')
    ap.add_argument('--poll-seconds', type=int, default=60)
    a = ap.parse_args()
    owner, name = a.repo.split('/', 1)
    policy = load_policy(a.policy, name)
    ap_lanes = os.path.join(HERE, 'merge-gate-lanes.json')
    try:
        lanes = [x for x in json.load(open(a.lanes or ap_lanes)).get(name, []) if isinstance(x, dict)]
    except (OSError, ValueError):
        lanes = []
    rec = {'schema': 'MergeGateReceipt/v1', 'producer': 'dev-tools/gated-merge.py', 'captured_at_utc': dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), 'repo': a.repo, 'pr': a.pr, 'policy': policy, 'source': 'saved:' + a.from_json if a.from_json else 'github-graphql'}

    def done(code):
        rec['exit'] = code
        s = json.dumps(rec, indent=1)
        print(s)
        if a.receipt:
            open(a.receipt, 'w').write(s + '\n')
        return code

    def measure():
        if a.from_json:
            ans = json.load(open(a.from_json))
        else:
            ans, _ = reread_until_measured(lambda: read_answer(owner, name, a.pr), 3, 2.0)
            pr_ = (ans.get('repository') or {}).get('pullRequest') or {}
            dbr = ((ans.get('repository') or {}).get('defaultBranchRef') or {}).get('name')
            if pr_.get('headRefOid') and dbr:
                ans['base_compare'] = read_compare(a.repo, pr_['headRefOid'], current_base(ans) or dbr)
            spec = policy.get('disjoint_merge') or {}
            reason, _ = stale_base(ans, policy, lanes)
            if reason and spec.get('enabled') is True and a.repo_dir and a.impact_workdir:
                ans['disjoint_merge_proof'] = _merge_impact().collect(a.repo, a.repo_dir, a.graph_repo, pr_['headRefOid'], current_base(ans), spec, lanes, gh, a.impact_workdir)
            tier = (policy.get('stale_base_tiers') or {}).get('file_disjoint')
            if reason and tier and (tier.get('mode') in ('shadow', 'on')):
                try:
                    ans['stale_base_shadow'] = file_disjoint_shadow(read_pr_files(a.repo, current_base(ans) or dbr, pr_['headRefOid']), (ans.get('base_compare') or {}).get('files'), tier)
                except Exception as e:
                    ans['stale_base_shadow'] = {'mode': 'shadow', 'verdict': 'not_measured', 'merged_result_executed': False, 'reasons': [f'SHADOW_ERROR:{type(e).__name__}']}
            if a.dump_answer:
                json.dump(ans, open(a.dump_answer, 'w'), indent=1)
        return (ans, read_jobs(a.repo, failing_ids(ans, policy), a.jobs_dir if a.from_json else None))
    if a.expect_sha is not None:
        full = full_sha(a.expect_sha)
        if full is None:
            got = a.expect_sha.strip()
            rec.update(verdict='NOT_MEASURED', expect_sha=got, reasons=[f'EXPECT_SHA_NOT_FULL:{got!r} is {len(got)} chars; a full 40-hex SHA is required'])
            print(f'gated-merge: NOT MEASURED {a.repo}#{a.pr} [bad input, exit 2] {rec['reasons'][0]} — pass the full head SHA: gh api repos/{a.repo}/pulls/{a.pr} --jq .head.sha', file=sys.stderr)
            return done(2)
        a.expect_sha = full
    if a.from_json:
        a.dry_run = True
    wait = max(0, min(a.rerun_wait, 3600))
    deadline = time.monotonic() + wait
    retried = {}
    rec['reruns'] = []
    expect = a.expect_sha
    while True:
        try:
            answer, jobs = measure()
        except Exception as e:
            rec.update(verdict='NOT_MEASURED', reasons=[f'API_UNREADABLE:{str(e)[:200]}'])
            print(f'gated-merge: NOT MEASURED {a.repo}#{a.pr} [exit 2] {rec['reasons'][0]} — nothing was judged or merged; check `gh auth status` and the network, then run the gate again', file=sys.stderr)
            return done(2)
        verdict, reasons, checks, causes = judge(answer, policy, expect, jobs, lanes)
        rec['base'] = stale_base(answer, policy, lanes)[1]
        if answer.get('stale_base_shadow'):
            rec['stale_base_shadow'] = answer['stale_base_shadow']
        pr = (answer['repository'] or {}).get('pullRequest') or {}
        expect = expect or pr.get('headRefOid')
        cls = refusal_class(causes)
        req_eff, req_src = admission_required(answer, policy)
        rec.update(required_effective=req_eff, required_source=req_src)
        rec.update(head_sha=pr.get('headRefOid'), private=answer['repository'].get('isPrivate'), checks=checks, verdict=verdict, reasons=reasons, causes=causes, refusal_class=cls)
        if verdict == 'ADMIT' or not a.rerun_cancelled or a.dry_run or (cls in ('merits', 'not_started')):
            break
        exhausted = []
        for c in causes:
            if c['class'] != 'cancelled':
                continue
            n, jid = (c['check'], c['job_id'])
            if n in retried and retried[n] != jid:
                exhausted.append(n)
            elif n in retried:
                continue
            elif (jobs.get(jid) or {}).get('run_attempt', 2) > 1:
                exhausted.append(n)
            else:
                how = rerun(a.repo, jid)
                rec['reruns'].append({'check': n, 'job_id': jid, 'result': how})
                if how == 'started':
                    retried[n] = jid
                elif how.startswith('error:'):
                    exhausted.append(n)
        if exhausted:
            reasons.append('RERUN_EXHAUSTED:' + ','.join(sorted(set(exhausted))))
            causes.append({'class': 'cancelled', 'reason': reasons[-1], 'note': 're-run at most once per job; look at the job before re-running by hand'})
            break
        if time.monotonic() >= deadline:
            reasons.append(f'RERUN_WAIT_LIMIT:{wait}s')
            causes.append({'class': cls, 'reason': reasons[-1]})
            break
        time.sleep(a.poll_seconds)
    if verdict != 'ADMIT':
        for c in causes:
            c['action'] = action_for(c)
        for k in ORDER:
            groups = {}
            for c in causes:
                if c['class'] == k:
                    groups.setdefault(c['action'], []).append(c['reason'])
            for act, mine in sorted(groups.items(), key=lambda g: g[0] != ACTION[k]):
                print(f'gated-merge: REFUSED {a.repo}#{a.pr} [{k}, exit {EXIT[k]}] ' + '; '.join(mine) + f' — {act}', file=sys.stderr)
        return done(EXIT[refusal_class(causes)])
    if a.dry_run:
        rec['merged'] = False
        rec['note'] = 'dry-run: would merge'
        return done(0)
    if answer.get('disjoint_merge_proof') is not None:
        fresh = read_answer(owner, name, a.pr)
        fresh_pr = (fresh.get('repository') or {}).get('pullRequest') or {}
        if fresh_pr.get('headRefOid') != pr.get('headRefOid') or current_base(fresh) != current_base(answer):
            rec.update(verdict='REFUSE', merged=False, reasons=['MERGE_INPUT_MOVED:head or base changed after graph proof'])
            return done(1)
        again, why, _, _ = judge(fresh, {**policy, 'max_behind': None}, expect, jobs, lanes)
        if again != 'ADMIT':
            rec.update(verdict=again, merged=False, reasons=why)
            return done(1)
    proof = answer.get('disjoint_merge_proof')
    if proof is not None:
        spec = policy.get('disjoint_merge') or {}
        if spec.get('publication') != 'atomic_refs_expected_old' or a.method != 'merge' or (not a.receipt):
            rec.update(verdict='NOT_MEASURED', merged=False, reasons=['DISJOINT_PUBLICATION_UNBOUND:reviewed mechanism, merge method and durable receipt required'])
            return done(2)

        def api_json(method, endpoint, body):
            args = ['gh', 'api', '-X', method, endpoint]
            if body is not None:
                args += ['--input', '-']
            response = subprocess.run(args, input=None if body is None else json.dumps(body), capture_output=True, text=True, timeout=60)
            if response.returncode:
                raise RuntimeError(f'GitHub {method} refused (rc {response.returncode}); no automatic mutation retry')
            return json.loads(response.stdout)
        try:
            result = _merge_impact().publish_exact_result(a.repo, a.repo_dir, a.pr, pr['baseRefName'], proof, api_json, a.receipt + '.intent')
            rec['atomic_refs_publication'] = result
            rec['merged'] = result['pr_merged']
            if not result['sealed']:
                rec.update(verdict='NOT_MEASURED', reasons=['PUBLICATION_READBACK_UNSEALED:inspect actual custody before any retry'])
                return done(2)
            return done(0)
        except Exception as exc:
            rec.update(verdict='NOT_MEASURED', merged=None, reasons=['DISJOINT_PUBLICATION_UNKNOWN:' + type(exc).__name__])
            return done(2)
    p = subprocess.run(['gh', 'api', '-X', 'PUT', f'repos/{a.repo}/pulls/{a.pr}/merge', '-f', f'sha={pr['headRefOid']}', '-f', f'merge_method={a.method}'], capture_output=True, text=True)
    rec['merge_api_rc'] = p.returncode
    rec['merge_api_answer'] = (p.stdout or p.stderr).strip()[:400]
    rec['merged'] = p.returncode == 0 and '"merged":true' in p.stdout.replace(' ', '')
    if not rec['merged']:
        print(f'gated-merge: merge call failed for {a.repo}#{a.pr} (admitted, not merged) [exit 2] rc={p.returncode} {rec['merge_api_answer'][:200]} — a 409 means the head moved after the verdict: run the gate again', file=sys.stderr)
        return done(2)
    return done(0)
if __name__ == '__main__':
    sys.exit(main())
