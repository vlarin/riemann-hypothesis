"""Run the single existing Core 25 worker upload through the reviewed Playground client."""
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import deliver

def send(row,secret):
    api=deliver.api
    if row['attempt']!=104668 or row['core']!=25 or row['worker_sha']!='16585fd2a847207ce32c1e882d3307fa4c8f2bfc37ec4ff38c08b8e0b9927d99' or row['worker_size']!=18626273:
        raise api.Hold('incorrect Core 25 attempt or archive')
    token=secret['token']
    with tempfile.TemporaryDirectory() as folder:
        work=Path(folder);api.unpack(row,work,secret)
        (work/'upload-auth').write_text(token)
        deadline=time.monotonic()+4*3600+45*60
        state=deliver.current(row,token,deadline)
        if state.get('authorId')!='vladyslav_larin' or state.get('challengeId')!=row['challenge_id'] or state.get('id')!=104668:
            raise api.Hold('official owner or challenge mismatch')
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
        same=(http==201 and re.fullmatch(r'[1-9][0-9]{0,18}',job) and str(reply.get('attempt_id'))=='104668'
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
