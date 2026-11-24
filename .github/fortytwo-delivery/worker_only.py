"""Fresh-gated character-based scoring, authorized Main-only hosted verification request."""
from datetime import datetime,timezone
from decimal import Decimal
import json
import hashlib
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
import live_board as lb

CID='lean-4-verification-riemann-hypothesis-levent-alpo-78ee076d'
BASE=980408459
PROOF='be16a8758e7466577694c7cd6958fc59a8d7ec4fce832d8c4ed1d118998f735c'
PROOFS={
    PROOF:(934089447,165111,368090219,'06432afa0b6851ce0287b25cf6d1a7ef5d48f12aaca3fdb14d565b3b91a972e2'),
    '2cf0de3581ea8c86944c600cd015f4042227f8b481edccfa6e5fbdb126ee93ed':(914505472,164434,363608708,'54e20bd287c996c34727ec8303e000f38850ffdbf71f1aa5e3d8c7b6d5ed6d57'),
}

def exact_package(row):
    return (row['chars'],row['files'],row['worker_size'],row['worker_sha'])==PROOFS.get(row['proof_id']) and (
        row['worker_size'],row['worker_sha'])==(row['platform_size'],row['platform_sha'])

def prediction(chars):
    if type(chars) is not int or chars<=0:raise ValueError('invalid Unicode character count')
    base=50/(1+.5*math.log10(max(chars,BASE)/min(chars,BASE)))
    return Decimal(str(100-base if chars<=BASE else base)).quantize(Decimal('0.000001'))

def main_board(row,token,exclude_attempt=None,confirm_attempt=False):
    if row['challenge_id']!=CID or row['core']!='main' or row['baseline_chars']!=BASE or row['proof_id'] not in PROOFS or (row['chars'],row['files'])!=PROOFS[row['proof_id']][:2]:
        raise ValueError('invalid Main target identity')
    best=Decimal(0);leader=None;ours=None;seen=set();prev=Decimal(101)
    for page in range(1,1001):
        listing=lb.get(f'/challenges/{CID}/attempts?sort=score&limit=20&page={page}',token)
        rows=listing.get('attempts')
        if not isinstance(rows,list):raise ValueError('missing Main rank page')
        for row0 in rows:
            aid=row0.get('id');display=lb.score(row0.get('score') or 0)
            if type(aid) is not int or aid in seen or row0.get('challengeId')!=CID or display>prev:raise ValueError('Main rank identity changed')
            seen.add(aid);prev=display
            if not display or display+lb.DISPLAY_TOLERANCE<best:continue
            item=lb.get('/attempts/'+str(aid),token);s=item.get('scoringState') or {};c=item.get('resultsJson') or {}
            if item.get('challengeId')!=CID or item.get('id')!=aid:raise ValueError('Main scorecard identity mismatch')
            if s.get('scoreIsFinal') is False:continue
            if not (item.get('status')=='scored' and s.get('state')=='final' and s.get('scoreIsFinal') is True and
                    s.get('overrideInEffect') is False and display==lb.score(item['score']) and c.get('baseline_chars')==BASE):
                raise ValueError('unconfirmed Main scorecard')
            historic=(aid==93193 and item.get('authorId')=='osgood' and c.get('accepted') is True and
                      c.get('scored_by')=='playground-worker/harbor-rh-official-baseline' and
                      c.get('scoring_policy')=='harbor_only_no_trace' and c.get('harbor_errors')==0 and
                      c.get('lean_files')==175187 and c.get('char_count')==BASE and c.get('harbor_score')==50)
            if not historic and not (c.get('harbor_status')=='scored' and c.get('score_is_final') is True):
                raise ValueError('unresolved official Main grader')
            raw=lb.score(c.get('final_score'))
            if abs(raw-display)>lb.DISPLAY_TOLERANCE or raw!=prediction(c.get('char_count')):
                raise ValueError('character projection or published score differs')
            if aid==exclude_attempt:ours=raw
            elif raw>best:best,leader=raw,aid
        if len(seen)>=listing.get('total',len(seen)+1) or (rows and (prev==0 or prev+lb.DISPLAY_TOLERANCE<best)):break
        if not rows:raise ValueError('incomplete Main leaderboard')
    else:raise ValueError('Main rank page limit')
    ourscore=prediction(row['chars'])
    return dict(leader=leader,leader_score=float(best),predicted_score=float(ourscore),eligible=ourscore>best,
                own_final_score=float(ours) if ours is not None else None,checked_at=datetime.now(timezone.utc).isoformat(),
                checked_rows=len(seen),score_unit='unicode_characters',chars=row['chars'],baseline_chars=BASE)

def send(row,secret):
    import deliver
    api=deliver.api
    if not (exact_package(row) and row['core']=='main' and row['challenge_id']==CID and row['baseline_chars']==BASE
            and type(row['attempt']) is int and row['attempt']>0 and row.get('main_hosted_verification') is True):
        raise api.Hold('Main archive identity mismatch')
    def gate(r,token,deadline):
        g=main_board(r,token,exclude_attempt=r['attempt']);api.log(r,'main_rank_gate',**g)
        if not g['eligible']:raise api.Hold('existing leader is no longer beaten')
    deliver.start_gate=gate
    token=secret['token']
    with tempfile.TemporaryDirectory() as name:
        work=Path(name);api.unpack(row,work,secret);(work/'upload-auth').write_text(token)
        deadline=time.monotonic()+4.75*3600
        def owner():
            item=deliver.current(row,token,deadline)
            if item.get('authorId')!='vladyslav_larin' or item.get('challengeId')!=CID or item.get('id')!=row['attempt'] or row['proof_id'] not in (item.get('detail') or ''):
                raise api.Hold('wrong official owner, proof or challenge')
            return item
        obj=owner()
        if obj.get('status')=='draft':
            if obj.get('bundleStatus')=='ready':raise api.Hold('unresolved earlier draft publication')
            with zipfile.ZipFile(work/'worker.zip') as archive:raw=archive.read('raw_messages.jsonl')
            if hashlib.sha256(raw).hexdigest()!=row['trace_body_sha'] or row['trace_manifest_sha']!=hashlib.sha256(b'{}').hexdigest():
                raise api.Hold('publication trace hash changed')
            (work/'raw_messages.jsonl').write_bytes(raw);(work/'manifest.json').write_bytes(b'{}')
            if not deliver.native_publish(row,token,work,deadline):raise api.Hold('ordinary native publication refused')
            obj=owner()
        if api.report_remote(row,obj):return
        q=obj.get('scoringQueue') or {};g=obj.get('scoringState') or {};res=obj.get('resultsJson') or {}
        if q.get('workerReceivedAt') or q.get('stage') in ('queued','received') or g.get('workerStatus') in ('queued','evaluating'):
            api.log(row,'already_in_worker_queue');return
        if obj.get('status')!='submitted' or res.get('lean_files') or g.get('scoreIsFinal'):raise api.Hold('closed native submission')
        gate(row,token,deadline)
        http,reply=deliver.transfer_file(row,token,work,'worker',deadline)
        job=str(reply.get('job_id',''));ok=(http==201 and re.fullmatch('[1-9][0-9]{0,18}',job) and
              str(reply.get('attempt_id'))==str(row['attempt']) and str(reply.get('bundle_bytes'))==str(row['worker_size']) and
              reply.get('bundle_sha256')==row['worker_sha'])
        api.log(row,'worker_receipt',http=http,exact_match=bool(ok),job=job if ok else None,
                sha256=row['worker_sha'] if ok else None,size=row['worker_size'] if ok else None)
        if not ok:raise api.Hold('worker receipt needs authentication')
if __name__=='__main__':
    import deliver
    os.umask(0o077);rows=json.loads(Path(sys.argv[1]).read_text())
    if len(rows)!=1:raise SystemExit('single article only')
    try:send(rows[0],json.loads(os.environ.pop('PLAYGROUND_RUN_INPUT')))
    except (ValueError,deliver.api.Hold) as e:
        deliver.api.log(rows[0],'held',reason=str(e)[:160]);sys.exit(1)
