"""Run the published proof archive through the reviewed Playground client."""
import json
import os
import hashlib
import zipfile
from pathlib import Path
import re
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import deliver

def send(row,secret):
    api=deliver.api
    if not (type(row['attempt']) is int and row['attempt'] > 0
            and type(row['core']) is int and row['core'] > 0 and row['core'] != 5
            and row.get('partial_trace_recovery') is True
            and row.get('prior_native_confirmed') is False
            and all(re.fullmatch('[a-f0-9]{64}',row[k]) for k in ('trace_body_sha','trace_manifest_sha'))
            and all(re.fullmatch('[0-9a-f]{64}', row[key]) for key in ('proof_id', 'worker_sha'))
            and row['worker_sha'] == row['platform_sha'] and row['worker_size'] == row['platform_size']
            and row['worker_size'] > 0):
        raise api.Hold('invalid signed archive catalog')
    token=secret['token']
    with tempfile.TemporaryDirectory() as folder:
        work=Path(folder);api.unpack(row,work,secret)
        (work/'upload-auth').write_text(token)
        deadline=time.monotonic()+4*3600+45*60
        state=deliver.current(row,token,deadline)
        if state.get('authorId')!='vladyslav_larin' or state.get('challengeId')!=row['challenge_id'] or state.get('id')!=row['attempt']:
            raise api.Hold('official owner or challenge mismatch')
        if state.get('status')=='draft':
            if (state.get('bundleStatus')=='ready' or state.get('bundleAvailable') or state.get('bundlePath')
                    or state.get('rawMessagesAvailable') or state.get('rawMessagesPath')):
                raise api.Hold('draft already has stored material; reconcile native evidence')
            with zipfile.ZipFile(work/'worker.zip') as archive:
                raw=archive.read('raw_messages.jsonl')
                full=archive.read('arm_manifest.json')
            manifest=full if hashlib.sha256(full).hexdigest()==row['trace_manifest_sha'] else b'{}'
            if hashlib.sha256(raw).hexdigest()!=row['trace_body_sha'] or hashlib.sha256(manifest).hexdigest()!=row['trace_manifest_sha']:
                raise api.Hold('native publication input checksum mismatch')
            (work/'raw_messages.jsonl').write_bytes(raw)
            (work/'manifest.json').write_bytes(manifest)
            if not deliver.native_publish(row,token,work,deadline):
                raise api.Hold('native publication not accepted')
            state=deliver.current(row,token,deadline)
            if state.get('id')!=row['attempt'] or state.get('authorId')!='vladyslav_larin' or state.get('challengeId')!=row['challenge_id']:
                raise api.Hold('changed official publication identity')
        if api.report_remote(row,state):return
        q=state.get('scoringQueue') or {}; grade=state.get('scoringState') or {}; result=state.get('resultsJson') or {}
        if q.get('stage') in ('queued','received') or q.get('workerReceivedAt') or grade.get('workerStatus') in ('queued','evaluating'):
            api.log(row,'already_in_worker_queue');return
        if result.get('lean_files') or grade.get('scoreIsFinal'):
            raise api.Hold('closed scorecard')
        if state.get('status')!='submitted' and not deliver.pending_worker(row,state,'native_harbor'):
            raise api.Hold('official state does not allow missing worker delivery')
        deliver.start_gate(row,token,deadline)
        api.log(row,'start_worker',bytes=row['worker_size'])
        http,reply=deliver.transfer_file(row,token,work,'worker',deadline)
        job=str(reply.get('job_id',''))
        same=(http==201 and re.fullmatch(r'[1-9][0-9]{0,18}',job) and str(reply.get('attempt_id'))==str(row['attempt'])
              and str(reply.get('bundle_bytes'))==str(row['worker_size']) and reply.get('bundle_sha256')==row['worker_sha'])
        api.log(row,'worker_receipt',http=http,job=job if same else None,exact_match=bool(same),
                sha256=row['worker_sha'] if same else None,size=row['worker_size'] if same else None)
        if not same:raise api.Hold('upload needs official reconciliation')

if __name__=='__main__':
    os.umask(0o077)
    cfg=json.loads(Path(sys.argv[1]).read_text())
    if len(cfg)!=1:raise SystemExit('invalid catalog')
    try:send(cfg[0],json.loads(os.environ.pop('PLAYGROUND_RUN_INPUT')))
    except deliver.api.Hold as exc:
        deliver.api.log(cfg[0],'held',reason=str(exc));sys.exit(1)
