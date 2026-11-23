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


def route(row, token):
    import live_board
    challenge = api.get(row,token,"/challenges/"+row["challenge_id"],"read_grader")
    if challenge.get("id") != row["challenge_id"]:
        raise api.Hold("official challenge identity mismatch")
    strategy = (challenge.get("scoring") or {}).get("strategy")
    if not isinstance(strategy,str) or not strategy:
        raise api.Hold("official scoring strategy unavailable")
    content = challenge.get("content") or ""
    instructions = isinstance(content,str) and re.search(r"playground\s+submit\b[^\n]*--outputs\b",content) and "/app/proof/Solution.lean" in content and "Harbor" in content
    if strategy == "harbor_external_verifier":
        return "native_harbor",strategy,"challenge_strategy"
    if strategy != "human_review_only" or not instructions:
        return "platform_only",strategy,"challenge_strategy"
    # A number of community RH cards say manual review even after their Harbor scorecards appear.
    try:
        leader = live_board.board(row,token).get("leader")
    except live_board.BoardUnavailable:
        raise api.Hold("unable to confirm read_board HTTP unavailable") from None
    finals=[leader] if leader is not None else []
    if not finals:
        listing=api.get(row,token,"/challenges/"+row["challenge_id"]+"/attempts?sort=score&limit=20","read_board").get("attempts")
        if not isinstance(listing,list) or any(a.get("challengeId")!=row["challenge_id"] for a in listing):
            raise api.Hold("invalid official grader witness list")
        finals=[a["id"] for a in listing if isinstance(a.get("id"),int) and (a.get("scoringState") or {}).get("scoreIsFinal") is True][:4]
    for leader in finals:
        other = api.get(row,token,"/attempts/"+str(leader),"read_leader")
        card = other.get("resultsJson") or {}
        if (other.get("id")==leader and other.get("challengeId")==row["challenge_id"]
                and (other.get("scoringState") or {}).get("scoreIsFinal") is True
                and card.get("score_is_final") is True and card.get("harbor_status")=="scored"):
            return "native_harbor",strategy,"published_task_and_final_harbor_attempt"
    for witness in row.get("harbor_witnesses",[]):
        a=api.get(row,token,"/attempts/"+str(witness["attempt"]),"read_grader_witness")
        if a.get("id")!=witness["attempt"] or a.get("challengeId")!=row["challenge_id"]:
            raise api.Hold("grader witness identity mismatch")
        q,s,card=(a.get(k) or {} for k in ("scoringQueue","scoringState","resultsJson"))
        counts=card.get("lean_files")==witness["files"] and card.get("char_count")==witness["chars"]
        if counts and ((q.get("stage")=="received" and s.get("workerStatus")=="evaluating")
                or (s.get("scoreIsFinal") is True and card.get("harbor_status")=="scored")):
            return "native_harbor",strategy,"published_task_and_observed_grader"
    return "arm_then_harbor",strategy,"published_task_without_confirmed_same_core_grader"


def native_publish(row, token, work, deadline):
    state=current(row,token,deadline)
    if state.get("status")!="draft":
        return True
    if row.get("prior_native_publish_unresolved"):
        # Never blindly redo an earlier publish whose outcome could not be determined.
        for _ in range(4):
            time.sleep(8)
            state=current(row,token,deadline)
            if state.get("status")!="draft":
                return True
        if state.get("bundleStatus")=="ready":
            raise api.Hold("previous native publication unresolved on ready draft")
        api.log(row,"native_reconciliation",observed_draft=True,switch_to_arm=True)
        return False
    fields=[]
    if state.get("bundleStatus")!="ready":
        fields=[("--form","raw_messages=@"+str(work/"raw_messages.jsonl")+";type=application/x-ndjson"),
                ("--form","manifest_json=<"+str(work/"manifest.json"))]
    start_gate(row,token,deadline)
    api.log(row,"native_publish_intent",saved_trace=not fields)
    code,reply=api.request(row,token,api.PLAY+"/attempts/"+str(row["attempt"])+"/submit",
                           "native_publish_response",fields=fields,method="POST",timeout=150)
    for i in range(12):
        state=current(row,token,deadline)
        if state.get("status") != "draft":
            row["native_confirmed_in_run"]=True
            api.log(row,"native_publish_confirmed",attempt_state=api.label(state.get("status")))
            return True
        if code in (400,409,413,415,422):
            # Server explicitly refused publication and an authenticated read confirms this ID is still a draft.
            api.log(row,"native_publish_refused",http=code,switch_to_arm=True)
            return False
        if code in (401,403,404,429):
            raise api.Hold("native publication HTTP "+str(code))
        if i<11:
            time.sleep(8)
    raise api.Hold("native publication outcome unconfirmed")


def pending_worker(row, state, selected):
    if state.get("status")!="pending_review":
        return False
    detail=(state.get("execLog") or "").lower()
    if not any(term in detail for term in ("bundle missing","never reached the evaluation worker")):
        return False
    native=(selected=="native_harbor" and (row.get("native_confirmed_in_run") or row.get("prior_native_confirmed")))
    return state.get("bundleStatus")=="ready" or bool(native)


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
    if kind == "platform" and code == 413:
        note=body[:8192].decode("utf-8",errors="replace")
        declared=re.findall(r"(?i)(?:maximum|max(?:imum)?[_ -]?(?:file[_ -]?)?size|limit(?:ed)?(?: to)?|上限|最大)\s*[\x22:=：、,( ]*([1-9][0-9.]{0,12})\s*(bytes?|[kmg]i?b|兆字节)",note)
        api.log(row,"platform_size_rejection",reported_limits=declared[:3],wire_bytes=int(parts[1]) if len(parts)>1 else None)
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
            selected,strategy,basis=route(row,token)
            api.log(row,"official_grader_route",selected=selected,strategy=api.label(strategy),basis=basis)
            if row.get("prior_arm_publish_unresolved"):
                for _ in range(6):
                    if current(row,token,deadline).get("status")!="draft":
                        break
                    time.sleep(10)
                else:
                    raise api.Hold("previous ARM publication unresolved on same draft")
            if row.get("native_only_after_platform_413") and selected!="native_harbor":
                raise api.Hold("previously rejected ARM archive cannot be attached for this grader")
            if selected=="native_harbor":
                published=native_publish(row,token,work,deadline)
                if not published and row.get("native_only_after_platform_413"):
                    raise api.Hold("native publication requires a different ARM archive")
            stage=0
            while time.monotonic()<deadline:
                state=current(row,token,deadline)
                if api.report_remote(row,state):
                    return True
                if state.get("status")=="draft" and selected=="native_harbor" and published:
                    raise api.Hold("conflicting official state after native publication")
                if state.get("status")=="draft" and row.get("native_only_after_platform_413"):
                    raise api.Hold("previously rejected ARM archive cannot be retransmitted")
                if (state.get("scoringState") or {}).get("scoreIsFinal") or (state.get("status") not in ("draft","submitted","queued","scoring","running") and not pending_worker(row,state,selected)):
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
                    api.log(row,"arm_publish_intent",saved_trace=True)
                    code,_=api.request(row,token,row_url+"/submit","publish_saved_trace",method="POST",timeout=65)
                    for i in range(12):
                        state=current(row,token,deadline)
                        if state["status"]!="draft":
                            api.log(row,"arm_publish_confirmed",attempt_state=api.label(state.get("status")))
                            break
                        if code in (400,401,403,404,409,413,415,422,429):
                            api.log(row,"arm_publish_refused",http=code)
                            raise api.Hold("ready draft publication HTTP "+str(code))
                        if i<11:
                            time.sleep(8)
                    else:
                        raise api.Hold("ready draft publication outcome unconfirmed")
                    continue
                break
            if selected=="platform_only":
                state=current(row,token,deadline)
                if state.get("status")=="draft":
                    raise api.Hold("platform draft publication not confirmed")
                api.log(row,"platform_published",grader_strategy=api.label(strategy),awaiting_grade=True)
                return True
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
                if (state.get("scoringState") or {}).get("scoreIsFinal") or (state.get("status") not in ("submitted","queued","scoring","running") and not pending_worker(row,state,selected)):
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
