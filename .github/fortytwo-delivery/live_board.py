"""Fresh, read-only comparison with the public Playground challenge leaderboard."""

from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from email.utils import parsedate_to_datetime
import json
import math
import re
import time
import urllib.error
import urllib.request


PLAY = "https://play.bohrium.com/api"
PRECISION = Decimal("0.000001")
DISPLAY_TOLERANCE = Decimal("0.005001")
PAGE_SIZE = 20


class BoardUnavailable(ValueError):
    """The latest challenge leaderboard could not be established."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get(path, token):
    if not re.fullmatch(r"/(?:attempts/[0-9]+|challenges/[a-zA-Z0-9_-]+/attempts\?sort=score&limit=[0-9]+&page=[0-9]+)", path):
        raise BoardUnavailable("Invalid official read path")
    headers = {"Accept": "application/json", "Cache-Control": "no-cache", "User-Agent": "Fortytwo-RH-leaderboard/1"}
    if token:
        if any(c.isspace() for c in token):
            raise BoardUnavailable("Invalid campaign credential")
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(PLAY + path, headers=headers)
    opener = urllib.request.build_opener(NoRedirect())
    for i in range(2):
        try:
            with opener.open(req, timeout=24) as response:
                age = response.headers.get("Age")
                date = response.headers.get("Date")
                if (age and int(age) > 90) or (date and abs(time.time() - parsedate_to_datetime(date).timestamp()) > 150):
                    raise BoardUnavailable("Playground returned a stale scoreboard snapshot")
                payload = json.load(response)
            if not isinstance(payload, dict):
                raise BoardUnavailable("Invalid Playground response")
            return payload
        except urllib.error.HTTPError as exc:
            if i or exc.code not in (408, 429, 500, 502, 503, 504):
                raise BoardUnavailable("Playground read HTTP " + str(exc.code)) from None
        except (OSError, json.JSONDecodeError) as exc:
            if i:
                raise BoardUnavailable("Playground read failed: " + type(exc).__name__) from None
        time.sleep(1)


def score(value):
    try:
        number = Decimal(str(value))
        if number.is_finite() and 0 <= number <= 100:
            return number
    except (ValueError, InvalidOperation):
        pass
    raise BoardUnavailable("Invalid official score")


def final_score(item, cid, token, baseline_tokens, baseline_chars):
    record = item
    card = record.get("resultsJson") or {}
    state = record.get("scoringState") or {}
    if state.get("scoreIsFinal") is not True or card.get("score_is_final") is not True:
        record = get("/attempts/" + str(item["id"]), token)
        card = record.get("resultsJson") or {}
        state = record.get("scoringState") or {}
    if record.get("id") != item["id"] or record.get("challengeId") != cid:
        raise BoardUnavailable("Leader attempt identity mismatch")
    if state.get("scoreIsFinal") is False:
        return None
    if state.get("scoreIsFinal") is not True:
        raise BoardUnavailable("Unresolved leaderboard entry")
    display = score(record["score"])
    if abs(display - score(item["score"])) > DISPLAY_TOLERANCE:
        raise BoardUnavailable("Leaderboard changed during the read")
    if state.get("overrideInEffect"):
        raise BoardUnavailable("Manual score override requires comparison with the official result")
    if card.get("score_is_final") is not True or card.get("harbor_status") != "scored":
        raise BoardUnavailable("Official scorer has not confirmed leader precision")
    raw = score(card.get("final_score"))
    if abs(display - raw) > DISPLAY_TOLERANCE:
        raise BoardUnavailable("Leaderboard and scorecard disagree")
    if card.get("baseline_chars") is not None and int(card["baseline_chars"]) != baseline_chars:
        raise BoardUnavailable("Scorecard uses different baseline character count")
    if card.get("baseline_tokens") is not None and int(card["baseline_tokens"]) != baseline_tokens:
        raise BoardUnavailable("Scorecard uses different baseline token count")
    return raw


def board(record, token, exclude_attempt=None):
    """Return the best other final score and whether this source strictly improves it.

    Both sides use the grader's six decimal places. Character counts are reported
    as a diagnostic. Only normalized Lean tokens enter the published score.
    """
    cid = record["challenge_id"]
    tokens, baseline = int(record["tokens"]), int(record["baseline_tokens"])
    chars, baseline_chars = int(record["chars"]), int(record["baseline_chars"])
    if min(tokens, baseline, chars, baseline_chars) <= 0 or not re.fullmatch(r"[a-zA-Z0-9_-]+", cid):
        raise BoardUnavailable("Invalid challenge or proof counts")
    leader = None
    best = Decimal(0)
    seen = set()
    previous = None
    for page in range(1, 1001):
        path = f"/challenges/{cid}/attempts?sort=score&limit={PAGE_SIZE}&page={page}"
        payload = get(path, token)
        rows = payload.get("attempts")
        if not isinstance(rows, list):
            raise BoardUnavailable("Missing challenge leaderboard")
        for item in rows:
            if not isinstance(item, dict) or item.get("challengeId") != cid or not isinstance(item.get("id"), int) or item["id"] in seen:
                raise BoardUnavailable("Invalid or repeated official leaderboard row")
            seen.add(item["id"])
            visible = score(item.get("score") or 0)
            if previous is not None and visible > previous:
                raise BoardUnavailable("Official leaderboard is not sorted by score")
            previous = visible
            if item["id"] == exclude_attempt or visible == 0 or visible + DISPLAY_TOLERANCE < best:
                continue
            raw = final_score(item, cid, token, baseline, baseline_chars)
            if raw is not None and raw > best:
                best, leader = raw, item["id"]
        if len(seen) >= int(payload.get("total", len(seen) if len(rows) < PAGE_SIZE else len(seen)+1)):
            break
        if not rows:
            raise BoardUnavailable("Incomplete challenge leaderboard page")
        if previous == 0 or previous + DISPLAY_TOLERANCE < best:
            break
    else:
        raise BoardUnavailable("Challenge leaderboard pagination did not finish")
    ratio = math.log10(max(tokens, baseline) / min(tokens, baseline))
    base_score = 50 / (1 + .5 * ratio)
    predicted = Decimal(str(100 - base_score if tokens <= baseline else base_score)).quantize(PRECISION)
    return {"leader": leader, "leader_score": float(best), "predicted_score": float(predicted),
            "eligible": predicted > best.quantize(PRECISION), "checked_at": datetime.now(timezone.utc).isoformat(),
            "checked_rows": len(seen), "score_precision": 6, "char_delta_from_baseline": chars - baseline_chars,
            "source": PLAY + f"/challenges/{cid}/attempts?sort=score&limit={PAGE_SIZE}&page=1"}
