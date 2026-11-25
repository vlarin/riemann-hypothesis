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
    if row.get("delivery_input_layout") != "same-proof-v1" or row["worker_size"] != row["platform_size"] or row["worker_sha"] != row["platform_sha"]:
        raise Hold("single-input source identity differs")
    with zipfile.ZipFile(archive) as z:
        if z.namelist() != ["worker.zip"]:
            raise Hold("unexpected delivery input members")
        for kind in ("worker",):
            name = kind + ".zip"
            if z.getinfo(name).file_size != row[kind + "_size"]:
                raise Hold("ZIP length mismatch")
            with z.open(name) as src, (work / name).open("wb") as dst:
                shutil.copyfileobj(src, dst)
            if sha(work / name) != row[kind + "_sha"]:
                raise Hold("ZIP checksum mismatch")
    os.link(work / "worker.zip", work / "platform.zip")
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


def attempt(row, token):
    obj = get(row, token, "/attempts/" + str(row["attempt"]), "read_attempt")
    if obj.get("id") != row["attempt"] or obj.get("challengeId") != row["challenge_id"]:
        raise Hold("attempt identity mismatch")
    return obj


def report_remote(row, obj):
    q = obj.get("scoringQueue") or {}
    s = obj.get("scoringState") or {}
    card = obj.get("resultsJson") or {}
    exact = card.get("lean_files") == row["files"] and card.get("char_count") == row["chars"]
    final = s.get("scoreIsFinal") is True and card.get("harbor_status") == "scored"
    evaluating = q.get("stage") == "received" and s.get("workerStatus") == "evaluating" and exact
    received = evaluating or (final and exact)
    log(row, "platform_state", attempt_state=label(obj.get("status")), bundle_status=label(obj.get("bundleStatus")),
        queue=label(q.get("stage")), input_counts_match=exact, received=received, final=final,
        score=card.get("final_score") if final else None)
    return received

def bundle_state(data):
    values = [data.get(k) for k in ("bundle_status", "bundleStatus", "status", "state")]
    for k in ("bundle", "validation"):
        if isinstance(data.get(k), dict):
            values += [data[k].get(key) for key in ("status", "bundle_status", "state")]
    return next((v for v in values if isinstance(v, str) and v in
                 ("ready", "packaging", "incomplete", "needs_review", "failed")), None)


