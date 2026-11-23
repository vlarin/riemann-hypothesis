"""Deliver four authentic, hash-pinned proof bundles using existing Playground attempts."""
import concurrent.futures
import datetime
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import run as api


def fresh(row, token):
    import live_board
    try:
        verdict = live_board.board(row, token, exclude_attempt=row["attempt"])
    except live_board.BoardUnavailable:
        raise api.Hold("unable to confirm read_board HTTP unavailable") from None
    api.log(row, "leaderboard", predicted=verdict["predicted_score"], leader=verdict["leader"],
            leader_score=verdict["leader_score"], eligible=verdict["eligible"])
    if not verdict["eligible"]:
        raise api.Hold("fresh leader is no longer beaten")


def current(row, token, deadline):
    while time.monotonic() < deadline:
        try:
            return api.attempt(row, token)
        except api.Hold as exc:
            if not str(exc).startswith("unable to confirm read_attempt HTTP ") or str(exc).endswith(("401", "403", "404")):
                raise
        time.sleep(10)
    raise api.Hold("observation deadline")


def start_gate(row, token, deadline):
    while time.monotonic() < deadline:
        try:
            fresh(row, token)
            return
        except api.Hold as exc:
            if not str(exc).startswith("unable to confirm read_") or str(exc).endswith(("401", "403", "404")):
                raise
        time.sleep(15)
    raise api.Hold("leaderboard read deadline")


def transfer_file(row, token, work, kind, deadline):
    url = api.WORKER if kind == "worker" else api.PLAY + "/attempts/" + str(row["attempt"]) + "/bundle"
    args = ["curl", "--silent", "--show-error", "--http1.1", "--proto", "=http" if kind == "worker" else "=https",
            "--connect-timeout", "30", "--max-time", str(max(60,int(deadline-time.monotonic()))),
            "--speed-limit", "1", "--speed-time", "420", "--keepalive-time", "30", "--header", "@-",
            "--header", "Accept: application/json", "--header", "Expect:", "--request", "POST"]
    if kind == "worker":
        args += ["--form-string", "attempt_id=" + str(row["attempt"]), "--form-string", "challenge_id=" + row["challenge_id"],
                 "--form", "playground_token=<" + str(work / "upload-auth")]
    args += ["--form", "bundle=@" + str(work / (kind + ".zip")) + ";filename=bundle.zip;type=application/zip",
             "--write-out", "\n%{http_code} %{size_upload} %{time_total}", url]
    api.log(row, "start_" + kind, bytes=row[kind + "_size"])
    result = subprocess.run(args,input=("Authorization: Bearer "+token+"\n").encode(),capture_output=True)
    body,_,stats = result.stdout.rpartition(b"\n")
    parts=stats.split()
    code=int(parts[0]) if parts and parts[0].isdigit() else 0
    try:
        reply=json.loads(body)
    except (ValueError,UnicodeError):
        reply={}
    if not isinstance(reply,dict):
        reply={}
    api.log(row, "transfer_" + kind, http=code, curl=result.returncode, bytes=int(parts[1]) if len(parts)>1 else None,
            seconds=float(parts[2]) if len(parts)>2 else None, bundle_state=api.bundle_state(reply))
    return code, reply


def retryable(code):
    return code in (0,408) or 500 <= code < 600


def follow(row, secret, deadline):
    token=secret["token"]
    try:
        with tempfile.TemporaryDirectory(prefix="verified-") as folder:
            work=Path(folder)
            api.unpack(row,work,secret)
            (work/"upload-auth").write_text(token)
            row_url=api.PLAY+"/attempts/"+str(row["attempt"])
            stage=0
            while time.monotonic()<deadline:
                state=current(row,token,deadline)
                if api.report_remote(row,state):
                    return True
                if (state.get("scoringState") or {}).get("scoreIsFinal") or (state.get("status") not in ("draft","submitted","queued","scoring","running") and not (state.get("status")=="pending_review" and state.get("bundleStatus")=="ready" and any(term in (state.get("execLog") or "").lower() for term in ("bundle missing","never reached the evaluation worker")))):
                    raise api.Hold("attempt already closed")
                if state.get("bundleStatus")=="needs_review":
                    raise api.Hold("platform requires human review")
                if state["status"]=="draft" and state.get("bundleStatus")!="ready":
                    if stage>=5:
                        raise api.Hold("platform transport retry limit")
                    start_gate(row,token,deadline)
                    code,reply=transfer_file(row,token,work,"platform",deadline)
                    stage+=1
                    if 200<=code<300:
                        outcome=api.bundle_state(reply)
                        if outcome not in ("ready","packaging",None):
                            raise api.Hold("platform validation: "+outcome)
                        for _ in range(10):
                            state=current(row,token,deadline)
                            if state.get("bundleStatus")=="ready":break
                            if state.get("bundleStatus") in ("needs_review","failed"):
                                raise api.Hold("platform validation requires attention")
                            time.sleep(4)
                    elif not retryable(code):
                        raise api.Hold("platform attachment HTTP "+str(code))
                    else:
                        time.sleep(5)
                    continue
                if state["status"]=="draft":
                    start_gate(row,token,deadline)
                    code,_=api.request(row,token,row_url+"/submit","publish_saved_trace",method="POST",timeout=65)
                    state=current(row,token,deadline)
                    if state["status"]=="draft" and not retryable(code):
                        raise api.Hold("ready draft publication HTTP "+str(code))
                    if state["status"]=="draft":
                        time.sleep(8)
                    continue
                break
            for retry in range(5):
                if time.monotonic()>=deadline:
                    break
                state=current(row,token,deadline)
                if api.report_remote(row,state):return True
                while ((state.get("scoringQueue") or {}).get("stage") in ("queued","received")
                       and (state.get("scoringState") or {}).get("workerStatus") in ("queued","evaluating")
                       and time.monotonic()<deadline):
                    time.sleep(15)
                    state=current(row,token,deadline)
                    if api.report_remote(row,state):return True
                if state.get("status")=="draft" or (state.get("scoringState") or {}).get("scoreIsFinal"):
                    raise api.Hold("attempt is no longer awaiting a worker")
                start_gate(row,token,deadline)
                code,ack=transfer_file(row,token,work,"worker",deadline)
                if 200<=code<300:
                    job=api.label(ack.get("job_id"))
                    match=(str(ack.get("attempt_id"))==str(row["attempt"]) and ack.get("bundle_sha256")==row["worker_sha"]
                           and str(ack.get("bundle_bytes"))==str(row["worker_size"]))
                    api.log(row,"worker_receipt",job=job,exact_match=match,worker_status=api.label(ack.get("status")),
                            sha256=row["worker_sha"] if match else None,size=row["worker_size"] if match else None,
                            response_fields=sorted(k for k in ack if api.label(k)))
                    if job and match:return True
                    for _ in range(7):
                        time.sleep(5)
                        if api.report_remote(row,current(row,token,deadline)):return True
                    raise api.Hold("worker acknowledgment could not be reconciled")
                if not retryable(code):
                    raise api.Hold("worker intake HTTP "+str(code))
                time.sleep(8*(retry+1))
            raise api.Hold("worker transport window ended")
    except api.Hold as exc:
        api.log(row,"held",reason=str(exc))
    except Exception as exc:
        api.log(row,"held",reason=type(exc).__name__)
    return False


if __name__=="__main__":
    os.umask(0o077)
    secret=json.loads(os.environ.pop("PLAYGROUND_RUN_INPUT"))
    if not secret["token"] or any(c.isspace() for c in secret["token"]):
        raise SystemExit("invalid run credential")
    rows=json.loads(Path(sys.argv[1]).read_text())
    deadline=time.monotonic()+4*3600+48*60
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(rows)) as pool:
        results=list(pool.map(lambda row:follow(row,secret,deadline),rows))
    sys.exit(0 if all(results) else 1)
