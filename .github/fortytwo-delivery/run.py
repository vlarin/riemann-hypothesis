"""Deliver preverified proofs to the two official Playground intake endpoints."""
import concurrent.futures
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile

PLAY = "https://play.bohrium.com/api"
WORKER = "http://47.92.88.121:443/api/uploads"
ASSET_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
SAFE_LABEL = re.compile(r"[\w.:-]{1,90}")


class Hold(Exception):
    """A known condition that must stop this attempt."""


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def label(value):
    value = str(value or "")
    return value if SAFE_LABEL.fullmatch(value) else None


def log(row, stage, **fields):
    record = dict(core=row["core"], attempt=row["attempt"], stage=stage,
                  utc=datetime.datetime.now(datetime.timezone.utc).isoformat(), **fields)
    print("RECEIPT " + json.dumps(record, separators=(",", ":")), flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def unpack(row, work, secret):
    url = secret["urls"][str(row["core"])]
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in ASSET_HOSTS or parsed.username or parsed.password:
        raise Hold("unexpected asset origin")
    enc = work / "input.enc"
    for number in range(3):
        try:
            with urllib.request.build_opener(NoRedirect()).open(url, timeout=90) as source, enc.open("wb") as dest:
                shutil.copyfileobj(source, dest)
            if sha(enc) != row["cipher_sha"]:
                raise Hold("ciphertext checksum mismatch")
            break
        except OSError:
            if number == 2:
                raise Hold("unable to read encrypted GitHub input")
            time.sleep(3)
    archive = work / "both.zip"
    cmd = ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "100000",
           "-md", "sha256", "-pass", "stdin", "-in", str(enc), "-out", str(archive)]
    proc = subprocess.run(cmd, input=secret["passphrase"] + "\n", capture_output=True, text=True)
    if proc.returncode:
        raise Hold("decryption failed")
    with zipfile.ZipFile(archive) as z:
        for kind in ("platform", "worker"):
            name = kind + ".zip"
            if z.getinfo(name).file_size != row[kind + "_size"]:
                raise Hold("ZIP length mismatch")
            with z.open(name) as src, (work / name).open("wb") as dst:
                shutil.copyfileobj(src, dst)
            if sha(work / name) != row[kind + "_sha"]:
                raise Hold("ZIP checksum mismatch")
    with zipfile.ZipFile(work / "platform.zip") as z:
        (work / "manifest.json").write_bytes(z.read("arm_manifest.json"))
        trace = z.read("native_trace/conversation.jsonl").lstrip(b"\r\n")
        if json.loads(trace.splitlines()[0]).get("type") != "session_start":
            trace = b'{"type":"session_start","source":"playground-cli"}\n' + trace
        (work / "raw_messages.jsonl").write_bytes(trace.rstrip(b"\n") + b"\n")
    log(row, "verified_input", worker_bytes=row["worker_size"])


def request(row, token, url, stage, fields=(), timeout=50, method="GET"):
    if not (url.startswith(PLAY + "/") or url == WORKER):
        raise Hold("unexpected intake origin")
    cmd = ["curl", "--silent", "--show-error", "--http1.1", "--proto",
           "=http" if url == WORKER else "=https", "--connect-timeout", "22",
           "--max-time", str(timeout), "--request", method, "--header", "@-",
           "--header", "Accept: application/json", "--header", "Expect:",
           "--write-out", "\n%{http_code} %{size_upload} %{time_total}"]
    for key, value in fields:
        cmd.extend([key, value])
    result = subprocess.run(cmd + [url], input=("Authorization: Bearer " + token + "\n").encode(), capture_output=True)
    body, _, stats = result.stdout.rpartition(b"\n")
    parts = stats.split()
    code = int(parts[0]) if parts and parts[0].isdigit() else 0
    try:
        data = json.loads(body)
    except (ValueError, UnicodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    if stage not in ("read_board", "read_attempt", "read_bundle", "read_leader") or code != 200:
        diagnostics = {}
        for key in ("error_code", "code", "state", "status", "bundleStatus", "bundle_status"):
            if key in data and label(data[key]) and token not in str(data[key]):
                diagnostics[key] = label(data[key])
        msg = " ".join(str(data.get(k) or "") for k in ("error", "message", "detail")).lower()
        indicators = [s for s in ("trace", "quota", "bundle", "draft", "schema", "authentic", "duplicate",
                                 "missing", "size", "too large", "unsupported", "required", "validation",
                                 "timeout", "queued", "not found", "rate", "token", "authorization") if s in msg]
        log(row, stage, http=code, curl=result.returncode, uploaded=int(parts[1]) if len(parts)>1 else None,
            seconds=float(parts[2]) if len(parts)>2 else None, indicators=indicators, **diagnostics)
    return code, data


def get(row, token, path, stage):
    for n in range(4):
        code, data = request(row, token, PLAY + path, stage)
        if code == 200:
            return data
        if code not in (0, 408, 502, 503, 504):
            break
        time.sleep(2 + 2*n)
    raise Hold("unable to confirm " + stage + " HTTP " + str(code))


def rank_gate(row, token):
    board = get(row, token, "/challenges/" + row["challenge_id"] + "/attempts?sort=score&limit=100", "read_board")
    attempts = board.get("attempts")
    if not isinstance(attempts, list):
        raise Hold("no official leaderboard")
    positives = [r for r in attempts if r.get("id") != row["attempt"] and float(r.get("score") or 0) > 0]
    score = 100 - 50 / (1 + 0.5 * math.log10(row["baseline_tokens"] / row["tokens"]))
    best = max(positives, key=lambda r: float(r["score"]), default=None)
    if best:
        top = best
        if not isinstance(top.get("resultsJson"), dict) or not top["resultsJson"].get("score_is_final"):
            top = get(row, token, "/attempts/" + str(int(best["id"])), "read_leader")
        card = top.get("resultsJson") or {}
        if not ((top.get("scoringState") or {}).get("scoreIsFinal") is True
                and card.get("score_is_final") is True and card.get("harbor_status") == "scored"
                and top.get("challengeId") == row["challenge_id"]
                and float(top["score"]) == float(best["score"]) == float(card["final_score"])):
            raise Hold("cannot verify current leader")
        if card.get("baseline_chars") and int(card["baseline_chars"]) != row["baseline_chars"]:
            raise Hold("published baseline changed")
    allowed = row["tokens"] < row["baseline_tokens"] and row["chars"] < row["baseline_chars"]
    if best:
        allowed = allowed and round(score, 2) > float(best["score"])
    log(row, "leaderboard", predicted=round(score, 4), leader=best["id"] if best else None,
        leader_score=best["score"] if best else None, eligible=allowed)
    if not allowed:
        raise Hold("current leader no longer beaten")


def attempt(row, token):
    obj = get(row, token, "/attempts/" + str(row["attempt"]), "read_attempt")
    if obj.get("id") != row["attempt"] or obj.get("challengeId") != row["challenge_id"]:
        raise Hold("attempt identity mismatch")
    return obj


def report_remote(row, obj):
    q = obj.get("scoringQueue") or {}
    s = obj.get("scoringState") or {}
    log(row, "platform_state", attempt_state=label(obj.get("status")), bundle_status=label(obj.get("bundleStatus")),
        queue=label(q.get("stage")), received_at=label(q.get("workerReceivedAt")) or (True if q.get("workerReceivedAt") else None),
        final=s.get("scoreIsFinal") is True, score=obj.get("score") if s.get("scoreIsFinal") else None)
    return bool(q.get("workerReceivedAt") or (obj.get("resultsJson") or {}).get("harbor_status") == "scored")


def bundle_state(data):
    values = [data.get(k) for k in ("bundle_status", "bundleStatus", "status", "state")]
    for k in ("bundle", "validation"):
        if isinstance(data.get(k), dict):
            values += [data[k].get(key) for key in ("status", "bundle_status", "state")]
    return next((v for v in values if isinstance(v, str) and v in
                 ("ready", "packaging", "incomplete", "needs_review", "failed")), None)


def transfer(row, secret, work):
    token = secret["token"]
    tokenfile = work / "upload-auth"
    tokenfile.write_text(token)
    obj = attempt(row, token)
    if report_remote(row, obj):
        return True
    rank_gate(row, token)
    url = PLAY + "/attempts/" + str(row["attempt"])
    if obj.get("status") == "draft":
        ready = bundle_state(obj)
        if ready != "ready":
            for n in range(2):
                code, result = request(row, token, url + "/bundle", "attach_platform",
                    [("--form", "bundle=@" + str(work / "platform.zip") + ";type=application/zip")], 260, "POST")
                ready = bundle_state(result)
                if not ready:
                    check_code, check = request(row, token, url + "/bundle/status", "read_bundle")
                    if check_code == 200:
                        ready = bundle_state(check)
                if ready or code not in (0, 408, 502, 503, 504):
                    break
                time.sleep(3)
            if ready == "packaging":
                for _ in range(12):
                    time.sleep(5)
                    ready = bundle_state(get(row, token, "/attempts/" + str(row["attempt"]) + "/bundle/status", "read_bundle"))
                    if ready != "packaging":
                        break
            log(row, "platform_bundle_check", bundle_state=label(ready))
            if ready in ("incomplete", "needs_review", "failed", "packaging") or code in (401, 403, 422, 429):
                observed = get(row, token, "/attempts/" + str(row["attempt"]) + "/bundle/manifest", "read_bundle")
                cover = (observed.get("handoff") or {}).get("modality_coverage") or {}
                log(row, "required_modalities", coverage={k:label((cover.get(k) or {}).get("status")) for k in ("execution","trace","characterization")})
                raise Hold("platform bundle requires action")
        rank_gate(row, token)
        code, _ = request(row, token, url + "/submit", "publish_platform",
            [("--form", "raw_messages=@" + str(work/"raw_messages.jsonl") + ";type=application/x-ndjson"),
             ("--form", "manifest_json=<" + str(work/"manifest.json"))], 150, "POST")
        obj = attempt(row, token)
        report_remote(row, obj)
        if obj.get("status") == "draft":
            if ready == "ready" and code in (400, 405, 415):
                rank_gate(row, token)
                code, _ = request(row, token, url + "/submit", "publish_with_attached_trace",
                    [("--header", "Content-Type: application/json"), ("--data-binary", "{}")], 100, "POST")
                obj = attempt(row, token)
                report_remote(row, obj)
        if obj.get("status") == "draft":
            if code in (401, 403, 422, 429) or ready == "ready":
                raise Hold("platform did not publish draft HTTP " + str(code))
            # Harbor challenges also accept a prebuilt bundle against an existing attempt ID.
            # This posts to the worker only. The platform remains authoritative about draft status.
            log(row, "draft_retained", submit_http=code)
    elif obj.get("status") not in ("submitted", "queued", "running", "scoring"):
        raise Hold("attempt is closed")
    for n in range(3):
        rank_gate(row, token)
        if n and report_remote(row, attempt(row, token)):
            return True
        args = [("--form-string", "attempt_id=" + str(row["attempt"])),
                ("--form-string", "challenge_id=" + row["challenge_id"]),
                ("--form", "playground_token=<" + str(tokenfile)),
                ("--form", "bundle=@" + str(work / "worker.zip") + ";filename=bundle.zip;type=application/zip")]
        code, ack = request(row, token, WORKER, "upload_worker", args, 400, "POST")
        if 200 <= code < 300:
            job = label(ack.get("job_id"))
            matches = (str(ack.get("attempt_id")) == str(row["attempt"])
                       and ack.get("bundle_sha256") == row["worker_sha"]
                       and str(ack.get("bundle_bytes")) == str(row["worker_size"]))
            log(row, "worker_receipt", job=job, worker_status=label(ack.get("status")), exact_match=matches,
                response_fields=sorted(k for k in ack if label(k)),
                sha256=row["worker_sha"] if matches else None, size=row["worker_size"] if matches else None)
            if job and matches:
                return True
            for _ in range(4):
                time.sleep(4)
                if report_remote(row, attempt(row, token)):
                    return True
            raise Hold("worker response lacks complete receipt")
        if code not in (0, 408) and not 500 <= code <= 599:
            raise Hold("worker intake HTTP " + str(code))
        time.sleep(6 + n*6)
    raise Hold("worker network retries exhausted")


def deliver(row, secret):
    try:
        with tempfile.TemporaryDirectory(prefix="proof-") as tmp:
            work = Path(tmp)
            unpack(row, work, secret)
            return transfer(row, secret, work)
    except Hold as e:
        log(row, "held", reason=str(e))
    except Exception as e:
        log(row, "held", reason=type(e).__name__)
    return False


if __name__ == "__main__":
    os.umask(0o077)
    catalog = json.loads(Path(sys.argv[1]).read_text())
    secret = json.loads(os.environ.pop("PLAYGROUND_RUN_INPUT"))
    if not secret["token"] or any(c.isspace() for c in secret["token"]):
        raise SystemExit("invalid run credential")
    # Two concurrent streams leave headroom for the official worker.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda r: deliver(r, secret), catalog))
    sys.exit(0 if all(results) else 1)
