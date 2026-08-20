#!/usr/bin/env python3
import hashlib
import html
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import parse_qs, quote, unquote, urlparse

import requests

# --- Config ---
USER_AGENT = "WikimediaDailyWatcher/1.0"
LAST_RUN_FILE = "last_run.txt"
PAGE_LIST_FILE = "page_list.txt"
PENDING_REPORT_FILE = "pending_report.json"
TELEGRAM_API = "https://api.telegram.org"
TELEGRAPH_API = "https://api.telegra.ph"
EXCLUDED_USERS = {'SuperGrey', 'MediaWiki message delivery'}
HIDE_BOT_EDITS = True
REVISION_SETTLE_SECONDS = 120
TELEGRAPH_CONTENT_LIMIT_BYTES = 64 * 1024
# Leave room for any server-side representation differences below the documented limit.
TELEGRAPH_CONTENT_BUDGET_BYTES = 63 * 1024
TELEGRAM_MESSAGE_LIMIT_CHARS = 4096
PENDING_REPORT_VERSION = 1

# Read secrets from env (set these in GitHub Actions Secrets)
TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAPH_ACCESS_TOKEN = os.environ.get("TELEGRAPH_ACCESS_TOKEN", "")

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


class RevisionFetchError(RuntimeError):
    """A watched page could not be queried reliably."""


class TelegraphPublishError(RuntimeError):
    """A Telegraph report could not be rendered, resumed, or published."""


class PendingReportError(RuntimeError):
    """The durable delivery state is invalid or inconsistent."""


def _parse_iso_timestamp(value):
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty string")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_utc_iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _write_text_atomic(path, text):
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)


def read_last_run_iso(path=LAST_RUN_FILE):
    if not os.path.exists(path):
        # default to 7 days back on first run
        return _format_utc_iso(datetime.now(timezone.utc) - timedelta(days=7))
    with open(path, "r", encoding="utf-8") as f:
        value = f.read().strip()
    try:
        return _format_utc_iso(_parse_iso_timestamp(value))
    except Exception as e:
        raise PendingReportError(f"Invalid reporting watermark in {path}") from e


def parse_page_list(path):
    """
    Returns:
      groups: { group_name: [ { 'url', 'domain', 'title' } ] }
      order:  [group_name] (to maintain order)
    """
    groups = {}
    order = []
    current_group = "Ungrouped"
    groups[current_group] = []
    order.append(current_group)

    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                name = line[1:].strip() or "Untitled"
                current_group = name
                if name not in groups:
                    groups[name] = []
                    order.append(name)
                continue
            url = line
            domain, title = parse_wiki_url(url)
            if domain and title:
                groups[current_group].append({"url": url, "domain": domain, "title": title})
            else:
                logging.warning(f"Skipping unparsable line: {line}")

    return groups, order


def parse_wiki_url(url):
    """
    Supports:
      https://<domain>/wiki/Title
      https://<domain>/w/index.php?title=Title
      Also tolerates fragments and query args.
    Returns: (domain, normalized_title) or (None, None)
    """
    try:
        u = urlparse(url)
        if not u.scheme.startswith("http"):
            return (None, None)
        domain = u.netloc

        # Path-based
        if u.path.startswith("/wiki/"):
            title = u.path[len("/wiki/"):]
            title = title.replace("_", " ")
            title = unquote(title)
            return (domain, title)

        # Query title
        if u.path.startswith("/w/") or u.path.endswith("index.php"):
            qs = parse_qs(u.query)
            if "title" in qs and qs["title"]:
                title = qs["title"][0]
                title = title.replace("_", " ")
                title = unquote(title)
                return (domain, title)

        # Fallback: if there's a 'curid' or similar, we skip (out of scope)
        return (None, None)
    except Exception:
        return (None, None)


def api_endpoint_for_domain(domain):
    return f"https://{domain}/w/api.php"


def chunk(iterable, n):
    it = list(iterable)
    for i in range(0, len(it), n):
        yield it[i:i + n]


def _is_bot_revision(rev):
    """Heuristics to identify bot edits.
    MediaWiki returns 'bot' as a key if rvprop includes flags and the edit has the bot flag.
    Additionally, some bot edits have 'bot' in tags or username ending with 'bot'."""
    user = (rev.get("user") or "").lower()
    if 'bot' in rev:  # flag style
        return True
    tags = rev.get("tags", []) or []
    if any(t.lower() == 'bot' for t in tags):
        return True
    if user.endswith('bot'):
        return True
    return False


def _filter_revisions(revs):
    if not revs:
        return revs
    original = len(revs)
    filtered = []
    for r in revs:
        user = r.get("user") or ""
        if user in EXCLUDED_USERS:
            logging.info(f"Excluding revision {r.get('revid')} by excluded user {user}")
            continue
        if HIDE_BOT_EDITS and _is_bot_revision(r):
            logging.info(f"Excluding revision {r.get('revid')} by bot user {user}")
            continue
        filtered.append(r)
    removed = original - len(filtered)
    if removed:
        logging.info(f"Filtered out {removed} revision(s) (excluded users/bots)")
    return filtered


def _retry_after_seconds(response):
    """Return server-directed retry delay in seconds, if provided."""
    if response is None:
        return None

    retry_after = response.headers.get("Retry-After")
    if not retry_after:
        return None

    # Retry-After can be either integer seconds or an HTTP-date.
    try:
        secs = int(retry_after)
        return max(1, secs)
    except (TypeError, ValueError):
        pass

    try:
        retry_dt = parsedate_to_datetime(retry_after)
        if retry_dt.tzinfo is None:
            retry_dt = retry_dt.replace(tzinfo=timezone.utc)
        wait = int((retry_dt - datetime.now(timezone.utc)).total_seconds())
        return max(1, wait)
    except Exception:
        return None


def fetch_revisions_since(session, domain, title, since_iso, until_iso, max_retries=5):
    """Fetch revisions in the half-open/closed interval ``(since, until]``.

    The caller uses a slightly delayed ``until`` watermark so revisions at the
    boundary have time to become visible before that watermark is committed.
    Any exhausted request or malformed API response raises RevisionFetchError;
    an API failure must never be interpreted as a page with no changes.
    """
    endpoint = api_endpoint_for_domain(domain)
    try:
        since_dt = _parse_iso_timestamp(since_iso)
        until_dt = _parse_iso_timestamp(until_iso)
    except (TypeError, ValueError) as e:
        raise RevisionFetchError(
            f"{domain} {title}: invalid reporting interval") from e

    if until_dt <= since_dt:
        return []

    params = {
        "action": "query",
        "format": "json",
        "prop": "revisions",
        "titles": title,
        "redirects": "1",
        "rvprop": "ids|timestamp|user|comment|size|flags|tags|sha1",
        "rvdir": "newer",  # chronological
        "rvstart": since_iso,
        "rvend": until_iso,
        "rvlimit": "50",
    }

    all_revs = []
    while True:
        data = None
        last_error = None
        for attempt in range(max_retries + 1):
            try:
                response = session.get(endpoint, params=params, timeout=30)
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict):
                    raise ValueError("API response is not a JSON object")
                if payload.get("error"):
                    api_error = payload["error"]
                    code = (api_error.get("code", "unknown")
                            if isinstance(api_error, dict) else "unknown")
                    raise ValueError(f"MediaWiki API error: {code}")
                data = payload
                break
            except requests.exceptions.HTTPError as e:
                last_error = e
                status = e.response.status_code if e.response is not None else "?"
                if isinstance(status, int) and 400 <= status < 500 and status != 429:
                    raise RevisionFetchError(
                        f"{domain} {title}: non-retriable API HTTP {status}") from e
                if attempt >= max_retries:
                    break
                sleep = _retry_after_seconds(e.response) or 2 ** (attempt + 1)
                logging.warning(
                    f"{domain} {title}: API HTTP {status} error; retrying in {sleep}s...")
                time.sleep(sleep)
            except Exception as e:
                last_error = e
                if attempt >= max_retries:
                    break
                sleep = 2 ** (attempt + 1)
                logging.warning(
                    f"{domain} {title}: API error {type(e).__name__}; retrying in {sleep}s...")
                time.sleep(sleep)

        if data is None:
            detail = type(last_error).__name__ if last_error is not None else "unknown error"
            raise RevisionFetchError(
                f"{domain} {title}: API failed after {max_retries + 1} attempt(s) ({detail})")

        query = data.get("query")
        if not isinstance(query, dict):
            raise RevisionFetchError(f"{domain} {title}: response has no query result")
        pages = query.get("pages")
        if not isinstance(pages, dict):
            raise RevisionFetchError(f"{domain} {title}: malformed pages response")
        for _, p in pages.items():
            if not isinstance(p, dict):
                raise RevisionFetchError(f"{domain} {title}: malformed page response")
            revs = p.get("revisions", [])
            if not isinstance(revs, list):
                raise RevisionFetchError(f"{domain} {title}: malformed revisions response")
            all_revs.extend(revs)

        continuation = data.get("continue", {})
        if not isinstance(continuation, dict):
            raise RevisionFetchError(f"{domain} {title}: malformed continuation response")
        cont = continuation.get("rvcontinue")
        if cont is not None and not isinstance(cont, str):
            raise RevisionFetchError(f"{domain} {title}: invalid continuation token")
        if cont:
            params["rvcontinue"] = cont
        else:
            break

    # MediaWiki's timestamp bounds are inclusive. Enforce our explicit window
    # locally and deduplicate continuation results by revision ID.
    window_revs = []
    seen_revids = set()
    for rev in all_revs:
        revid = rev.get("revid")
        timestamp = rev.get("timestamp")
        if revid is None or not timestamp:
            raise RevisionFetchError(f"{domain} {title}: revision is missing ID or timestamp")
        if revid in seen_revids:
            continue
        seen_revids.add(revid)
        try:
            revision_dt = _parse_iso_timestamp(timestamp)
        except (TypeError, ValueError) as e:
            raise RevisionFetchError(
                f"{domain} {title}: revision {revid} has an invalid timestamp") from e
        if since_dt < revision_dt <= until_dt:
            window_revs.append(rev)

    filtered_revs = _filter_revisions(window_revs)
    logging.info(
        f"{domain} {title}: {len(filtered_revs)} new rev(s) "
        f"(API returned: {len(all_revs)}) between {since_iso} and {until_iso}")
    return filtered_revs


def build_diff_url(domain, revid, parentid):
    if parentid is None:
        return f"https://{domain}/w/index.php?diff={revid}"
    return f"https://{domain}/w/index.php?diff={revid}&oldid={parentid}"


def collect_report_entries(order, group_payloads):
    """Flatten changed revisions while preserving group and page order."""
    entries = []
    changed_groups = set()
    changed_pages = set()
    for group_name in order:
        for page in group_payloads.get(group_name, []):
            revisions = page.get("revisions", [])
            if not revisions:
                continue
            changed_groups.add(group_name)
            page_key = (group_name, page["domain"], page["title"], page["url"])
            changed_pages.add(page_key)
            for revision in revisions:
                entries.append({
                    "group": group_name,
                    "page": page,
                    "revision": revision,
                })

    stats = {
        "group_count": len(changed_groups),
        "page_count": len(changed_pages),
        "revision_count": len(entries),
    }
    return entries, stats


def _revision_node(entry):
    page = entry["page"]
    revision = entry["revision"]
    timestamp = str(revision.get("timestamp") or "")
    user = str(revision.get("user") or "")
    comment = str(revision.get("comment") or "")
    diff_url = build_diff_url(
        page["domain"], revision.get("revid"), revision.get("parentid"))

    children = [
        "• ",
        {"tag": "code", "children": [timestamp]},
        " — ",
        {"tag": "strong", "children": [user]},
        ": ",
        comment,
        " (",
        {"tag": "a", "attrs": {"href": diff_url}, "children": ["diff"]},
        ")",
    ]
    return {"tag": "p", "children": children}


def render_telegraph_content(entries, since_iso, until_iso, stats, part_label=None):
    """Render report entries as Telegraph's DOM-based JSON node format."""
    nodes = [{
        "tag": "p",
        "children": [
            f"{stats['revision_count']} revision(s) across ",
            f"{stats['page_count']} page(s) in {stats['group_count']} group(s).",
        ],
    }, {
        "tag": "p",
        "children": [
            "Reporting window: after ",
            {"tag": "code", "children": [since_iso]},
            " through ",
            {"tag": "code", "children": [until_iso]},
            ".",
        ],
    }]
    if part_label:
        nodes.append({"tag": "p", "children": [
            {"tag": "strong", "children": [part_label]},
        ]})

    previous_group = None
    previous_page = None
    for entry in entries:
        group_name = entry["group"]
        page = entry["page"]
        page_key = (page["domain"], page["title"], page["url"])
        if group_name != previous_group:
            nodes.append({"tag": "h3", "children": [group_name]})
            previous_group = group_name
            previous_page = None
        if page_key != previous_page:
            nodes.append({
                "tag": "h4",
                "children": [{
                    "tag": "a",
                    "attrs": {"href": page["url"]},
                    "children": [page["title"]],
                }],
            })
            previous_page = page_key
        nodes.append(_revision_node(entry))
    return nodes


def serialize_telegraph_content(content):
    return json.dumps(
        content, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def telegraph_content_size(content):
    return len(serialize_telegraph_content(content).encode("utf-8"))


def paginate_telegraph_content(
        entries, since_iso, until_iso, stats,
        max_bytes=TELEGRAPH_CONTENT_BUDGET_BYTES):
    """Split a report at revision boundaries while retaining group/page context."""
    if not entries:
        return []

    single_page = render_telegraph_content(entries, since_iso, until_iso, stats)
    if telegraph_content_size(single_page) <= max_bytes:
        return [single_page]

    placeholder = "Part 9999 of 9999"
    chunks = []
    current = []
    for entry in entries:
        candidate = current + [entry]
        candidate_content = render_telegraph_content(
            candidate, since_iso, until_iso, stats, placeholder)
        if telegraph_content_size(candidate_content) <= max_bytes:
            current = candidate
            continue
        if not current:
            raise TelegraphPublishError(
                "A single revision cannot fit within the Telegraph content limit")
        chunks.append(current)
        current = [entry]
        first_content = render_telegraph_content(
            current, since_iso, until_iso, stats, placeholder)
        if telegraph_content_size(first_content) > max_bytes:
            raise TelegraphPublishError(
                "A single revision cannot fit within the Telegraph content limit")
    if current:
        chunks.append(current)

    if len(chunks) > 9999:
        raise TelegraphPublishError("Report requires more than 9999 Telegraph parts")

    contents = []
    total = len(chunks)
    for number, chunk_entries in enumerate(chunks, start=1):
        content = render_telegraph_content(
            chunk_entries, since_iso, until_iso, stats,
            f"Part {number} of {total}")
        if telegraph_content_size(content) > max_bytes:
            raise TelegraphPublishError(
                f"Rendered Telegraph part {number} exceeds the content budget")
        contents.append(content)
    return contents


def _telegraph_article_title(until_iso, part_number, total_parts):
    timestamp = until_iso.replace("T", " ").replace("Z", " UTC")
    title = f"Wikimedia changes through {timestamp}"
    if total_parts > 1:
        title += f" ({part_number}/{total_parts})"
    return title


def build_report_plan(order, group_payloads, since_iso, until_iso,
                      max_bytes=TELEGRAPH_CONTENT_BUDGET_BYTES):
    entries, stats = collect_report_entries(order, group_payloads)
    if not entries:
        return None
    contents = paginate_telegraph_content(
        entries, since_iso, until_iso, stats, max_bytes=max_bytes)

    parts = []
    total_parts = len(contents)
    for number, content in enumerate(contents, start=1):
        content_json = serialize_telegraph_content(content)
        parts.append({
            "title": _telegraph_article_title(until_iso, number, total_parts),
            "content": content,
            "content_json": content_json,
            "content_sha256": hashlib.sha256(content_json.encode("utf-8")).hexdigest(),
            "url": None,
        })

    plan_material = {
        "since": since_iso,
        "until": until_iso,
        "stats": stats,
        "content_sha256": [part["content_sha256"] for part in parts],
    }
    plan_id = hashlib.sha256(json.dumps(
        plan_material, separators=(",", ":"), sort_keys=True).encode("utf-8")).hexdigest()
    return {
        "version": PENDING_REPORT_VERSION,
        "since": since_iso,
        "until": until_iso,
        "stats": stats,
        "plan_id": plan_id,
        "parts": parts,
    }


def pending_state_from_plan(plan):
    parts = [{
        "title": part["title"],
        "content_sha256": part["content_sha256"],
        "url": part.get("url"),
    } for part in plan["parts"]]
    return {
        "version": plan["version"],
        "status": "ready" if all(part["url"] for part in parts) else "publishing",
        "since": plan["since"],
        "until": plan["until"],
        "stats": plan["stats"],
        "plan_id": plan["plan_id"],
        "parts": parts,
    }


def _is_telegraph_page_url(value):
    if not isinstance(value, str) or not value:
        return False
    parsed = urlparse(value)
    return (
        parsed.scheme == "https" and
        parsed.hostname == "telegra.ph" and
        bool(parsed.path and parsed.path != "/") and
        not parsed.username and
        not parsed.password
    )


def _validate_pending_state(state):
    if not isinstance(state, dict) or not state:
        raise PendingReportError("Pending report state must be a non-empty JSON object")
    if state.get("version") != PENDING_REPORT_VERSION:
        raise PendingReportError("Unsupported pending report state version")
    if state.get("status") not in {"publishing", "ready"}:
        raise PendingReportError("Pending report has an invalid status")
    for field in ("since", "until", "plan_id"):
        if not isinstance(state.get(field), str) or not state[field]:
            raise PendingReportError(f"Pending report is missing {field}")
    try:
        since_dt = _parse_iso_timestamp(state["since"])
        until_dt = _parse_iso_timestamp(state["until"])
    except ValueError as e:
        raise PendingReportError("Pending report has an invalid reporting interval") from e
    if until_dt <= since_dt:
        raise PendingReportError("Pending report interval is empty or reversed")
    if not re.fullmatch(r"[0-9a-f]{64}", state["plan_id"]):
        raise PendingReportError("Pending report has an invalid plan hash")
    stats = state.get("stats")
    if not isinstance(stats, dict) or any(
            not isinstance(stats.get(key), int) or stats[key] < 0
            for key in ("group_count", "page_count", "revision_count")):
        raise PendingReportError("Pending report has invalid statistics")
    if stats["revision_count"] == 0:
        raise PendingReportError("Pending report has no revisions")
    parts = state.get("parts")
    if not isinstance(parts, list) or not parts:
        raise PendingReportError("Pending report has no article parts")
    for part in parts:
        if not isinstance(part, dict):
            raise PendingReportError("Pending report contains an invalid article part")
        if not isinstance(part.get("title"), str) or not part["title"]:
            raise PendingReportError("Pending article part is missing its title")
        digest = part.get("content_sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PendingReportError("Pending article part has an invalid content hash")
        if part.get("url") is not None and not _is_telegraph_page_url(part["url"]):
            raise PendingReportError("Pending article part has an invalid URL")
    is_ready = all(part.get("url") for part in parts)
    if (state["status"] == "ready") != is_ready:
        raise PendingReportError("Pending report status does not match its article URLs")


def load_pending_report(path=PENDING_REPORT_FILE):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise PendingReportError(f"Cannot read {path}") from e
    if state == {}:
        return None
    _validate_pending_state(state)
    return state


def save_pending_report(state, path=PENDING_REPORT_FILE):
    if state:
        _validate_pending_state(state)
    serialized = json.dumps(state or {}, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _write_text_atomic(path, serialized)


def merge_pending_state(plan, state):
    """Verify a regenerated plan and copy already-published URLs into it."""
    expected = pending_state_from_plan(plan)
    for field in ("version", "since", "until", "stats", "plan_id"):
        if state.get(field) != expected.get(field):
            raise PendingReportError(
                f"Pending report no longer matches regenerated field: {field}")
    if len(state["parts"]) != len(plan["parts"]):
        raise PendingReportError("Pending report part count changed during recovery")
    for planned_part, saved_part in zip(plan["parts"], state["parts"]):
        if (planned_part["title"] != saved_part["title"] or
                planned_part["content_sha256"] != saved_part["content_sha256"]):
            raise PendingReportError("Pending report content changed during recovery")
        planned_part["url"] = saved_part.get("url")
    return plan


def _safe_telegraph_error(error):
    text = str(error)
    if TELEGRAPH_ACCESS_TOKEN:
        text = text.replace(TELEGRAPH_ACCESS_TOKEN, "[redacted]")
    return text[:200]


def _telegraph_error_wait(error):
    match = re.search(r"(?:FLOOD_WAIT|RETRY_AFTER)[^0-9]*(\d+)", str(error), re.IGNORECASE)
    return max(1, int(match.group(1))) if match else None


def _read_telegraph_api(session, method, data=None, max_retries=2):
    """Call a read-only Telegraph method with bounded retries."""
    endpoint = f"{TELEGRAPH_API}/{method}"
    for attempt in range(max_retries + 1):
        try:
            response = session.post(endpoint, data=data or {}, timeout=30)
            if response.status_code == 429:
                if attempt >= max_retries:
                    raise TelegraphPublishError(
                        f"Telegraph {method} was rate limited after retries")
                wait = _retry_after_seconds(response) or 2 ** (attempt + 1)
                time.sleep(wait)
                continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Telegraph response is not a JSON object")
            if not payload.get("ok"):
                error = payload.get("error", "unknown Telegraph error")
                wait = _telegraph_error_wait(error)
                if wait is not None and attempt < max_retries:
                    time.sleep(wait)
                    continue
                raise TelegraphPublishError(
                    f"Telegraph {method} failed: {_safe_telegraph_error(error)}")
            result = payload.get("result")
            if not isinstance(result, dict):
                raise TelegraphPublishError(
                    f"Telegraph {method} returned an invalid result")
            return result
        except TelegraphPublishError:
            raise
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "?"
            if (attempt >= max_retries or
                    (isinstance(status, int) and status < 500 and status not in {408, 429})):
                raise TelegraphPublishError(
                    f"Telegraph {method} failed with HTTP {status}") from e
            time.sleep(2 ** (attempt + 1))
        except (requests.exceptions.RequestException, ValueError) as e:
            if attempt >= max_retries:
                raise TelegraphPublishError(
                    f"Telegraph {method} failed after retries ({type(e).__name__})") from e
            time.sleep(2 ** (attempt + 1))
    raise TelegraphPublishError(f"Telegraph {method} failed after retries")


def _find_existing_telegraph_page(session, title, content_sha256):
    """Recover a createPage response lost after Telegraph accepted the page."""
    result = _read_telegraph_api(session, "getPageList", {
        "access_token": TELEGRAPH_ACCESS_TOKEN,
        "offset": 0,
        "limit": 200,
    })
    pages = result.get("pages", [])
    if not isinstance(pages, list):
        raise TelegraphPublishError("Telegraph getPageList returned invalid pages")
    for page_summary in pages:
        if not isinstance(page_summary, dict) or page_summary.get("title") != title:
            continue
        path = page_summary.get("path")
        if not isinstance(path, str) or not path:
            continue
        page = _read_telegraph_api(
            session, f"getPage/{quote(path, safe='')}", {"return_content": "true"})
        content = page.get("content")
        if not isinstance(content, list):
            continue
        serialized = serialize_telegraph_content(content)
        if hashlib.sha256(serialized.encode("utf-8")).hexdigest() == content_sha256:
            url = page.get("url") or page_summary.get("url")
            if _is_telegraph_page_url(url):
                return url
    return None


def create_telegraph_page(session, title, content, max_retries=3):
    """Create one Telegraph page, recovering ambiguous successful requests."""
    if not TELEGRAPH_ACCESS_TOKEN:
        raise TelegraphPublishError("TELEGRAPH_ACCESS_TOKEN is missing")
    content_json = serialize_telegraph_content(content)
    content_size = len(content_json.encode("utf-8"))
    if content_size > TELEGRAPH_CONTENT_LIMIT_BYTES:
        raise TelegraphPublishError(
            f"Telegraph content is {content_size} bytes; limit is {TELEGRAPH_CONTENT_LIMIT_BYTES}")
    content_sha256 = hashlib.sha256(content_json.encode("utf-8")).hexdigest()
    # Check first so a process crash after createPage but before saving its URL
    # can be recovered on the next workflow run without creating a duplicate.
    existing_url = _find_existing_telegraph_page(session, title, content_sha256)
    if existing_url:
        logging.info("Reusing an existing Telegraph page with matching content.")
        return existing_url

    endpoint = f"{TELEGRAPH_API}/createPage"
    request_data = {
        "access_token": TELEGRAPH_ACCESS_TOKEN,
        "title": title,
        "author_name": "Wikimedia Daily Watch",
        "content": content_json,
        "return_content": "false",
    }

    last_error = None
    for attempt in range(max_retries + 1):
        ambiguous_failure = False
        try:
            response = session.post(endpoint, data=request_data, timeout=30)
            if response.status_code == 429:
                if attempt >= max_retries:
                    raise TelegraphPublishError(
                        "Telegraph createPage was rate limited after retries")
                wait = _retry_after_seconds(response) or 2 ** (attempt + 1)
                time.sleep(wait)
                continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Telegraph response is not a JSON object")
            if not payload.get("ok"):
                error = payload.get("error", "unknown Telegraph error")
                wait = _telegraph_error_wait(error)
                if wait is not None and attempt < max_retries:
                    time.sleep(wait)
                    continue
                raise TelegraphPublishError(
                    f"Telegraph createPage failed: {_safe_telegraph_error(error)}")
            result = payload.get("result")
            url = result.get("url") if isinstance(result, dict) else None
            if not _is_telegraph_page_url(url):
                raise ValueError("Telegraph createPage result has no valid page URL")
            return url
        except TelegraphPublishError:
            raise
        except requests.exceptions.HTTPError as e:
            last_error = e
            status = e.response.status_code if e.response is not None else "?"
            if isinstance(status, int) and status < 500 and status not in {408, 429}:
                raise TelegraphPublishError(
                    f"Telegraph createPage failed with HTTP {status}") from e
            ambiguous_failure = True
        except (requests.exceptions.RequestException, ValueError) as e:
            last_error = e
            ambiguous_failure = True

        if ambiguous_failure:
            try:
                recovered_url = _find_existing_telegraph_page(
                    session, title, content_sha256)
            except TelegraphPublishError as recovery_error:
                logging.warning(
                    "Could not check whether Telegraph accepted an ambiguous createPage "
                    f"request ({type(recovery_error).__name__}).")
                recovered_url = None
            if recovered_url:
                logging.info("Recovered a Telegraph page after an ambiguous createPage response.")
                return recovered_url
            if attempt < max_retries:
                sleep = 2 ** (attempt + 1)
                logging.warning(
                    f"Telegraph createPage response was ambiguous; retrying in {sleep}s...")
                time.sleep(sleep)

    detail = type(last_error).__name__ if last_error is not None else "unknown error"
    raise TelegraphPublishError(
        f"Telegraph createPage failed after retries ({detail})")


def telegram_html_text_length(text):
    """Approximate Telegram's post-entity-parsing character count."""
    without_tags = re.sub(r"<[^>]*>", "", text)
    return len(html.unescape(without_tags))


def build_telegram_notification(state, max_chars=TELEGRAM_MESSAGE_LIMIT_CHARS):
    _validate_pending_state(state)
    if state["status"] != "ready":
        raise PendingReportError("Cannot notify for a report that is not fully published")

    stats = state["stats"]
    lines = [
        "<b>Wikimedia recent changes</b>",
        f"<code>{html.escape(state['since'])}</code> → "
        f"<code>{html.escape(state['until'])}</code>",
        f"{stats['group_count']} group(s) · {stats['page_count']} page(s) · "
        f"{stats['revision_count']} revision(s)",
        "",
    ]
    if len(state["parts"]) == 1:
        url = html.escape(state["parts"][0]["url"], quote=True)
        lines.append(f"<a href=\"{url}\">Open full report</a>")
    else:
        lines.append("Report articles:")
        total = len(state["parts"])
        for number, part in enumerate(state["parts"], start=1):
            url = html.escape(part["url"], quote=True)
            lines.append(f"<a href=\"{url}\">Part {number} of {total}</a>")

    message = "\n".join(lines)
    visible_length = telegram_html_text_length(message)
    if visible_length > max_chars:
        raise PendingReportError(
            f"Telegram notification is {visible_length} characters after entity parsing; "
            f"limit is {max_chars}")
    return message


def preflight_telegram_notification(plan):
    """Reject a part count that cannot be linked from one Telegram message."""
    preview = pending_state_from_plan(plan)
    for number, part in enumerate(preview["parts"], start=1):
        part["url"] = f"https://telegra.ph/pending-report-{number}"
    preview["status"] = "ready"
    build_telegram_notification(preview)


def send_telegram_message(session, text):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        logging.error("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing.")
        return False
    visible_length = telegram_html_text_length(text)
    if visible_length > TELEGRAM_MESSAGE_LIMIT_CHARS:
        logging.error(
            f"Telegram message is {visible_length} characters after entity parsing; "
            f"limit is {TELEGRAM_MESSAGE_LIMIT_CHARS}.")
        return False
    endpoint = f"{TELEGRAM_API}/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": False},
    }
    tries = 0
    while True:
        try:
            response = session.post(endpoint, json=payload, timeout=30)
            if response.status_code == 429:
                tries += 1
                if tries > 3:
                    logging.error("Telegram send remained rate limited after retries.")
                    return False
                retry_after = response.json().get("parameters", {}).get("retry_after", 3)
                time.sleep(int(retry_after) + 1)
                continue
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict) or not result.get("ok"):
                raise ValueError("Telegram response did not report success")
            return True
        except requests.exceptions.HTTPError as e:
            tries += 1
            status = e.response.status_code if e.response is not None else "?"
            if isinstance(status, int) and 400 <= status < 500:
                logging.error(f"Telegram send failed with non-retriable HTTP {status}.")
                return False
            if tries <= 3:
                sleep = 2 ** tries
                logging.warning(f"Telegram send HTTP {status}; retry in {sleep}s")
                time.sleep(sleep)
                continue
            logging.error("Telegram send failed after retries.")
            return False
        except Exception as e:
            tries += 1
            if tries <= 3:
                sleep = 2 ** tries
                logging.warning(f"Telegram send error ({type(e).__name__}); retry in {sleep}s")
                time.sleep(sleep)
                continue
            logging.error("Telegram send failed after retries.")
            return False


def _collect_group_payloads(session, groups, order, since_iso, until_iso):
    group_payloads = {}
    for group_name in order:
        prepared = []
        for page in groups.get(group_name, []):
            revisions = fetch_revisions_since(
                session, page["domain"], page["title"], since_iso, until_iso)
            prepared.append({**page, "revisions": revisions})
        group_payloads[group_name] = prepared
    return group_payloads


def _complete_delivery(state):
    # Advance the watermark before clearing the outbox. A crash between these
    # writes can duplicate a notification on retry, but cannot lose revisions.
    _write_text_atomic(LAST_RUN_FILE, state["until"] + "\n")
    save_pending_report({})
    logging.info(f"Updated {LAST_RUN_FILE} -> {state['until']}")
    logging.info(f"Cleared {PENDING_REPORT_FILE}")


def _notify_ready_report(session, state):
    notification = build_telegram_notification(state)
    if not send_telegram_message(session, notification):
        raise PendingReportError(
            "Telegram notification failed; the ready report remains pending")
    _complete_delivery(state)


def main():
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        pending = load_pending_report()
        if pending and pending["status"] == "ready":
            logging.info(
                f"Retrying Telegram delivery for {len(pending['parts'])} published article(s).")
            _notify_ready_report(session, pending)
            return

        if pending:
            since_iso = pending["since"]
            until_iso = pending["until"]
            logging.info(
                f"Resuming an incomplete Telegraph report from {since_iso} to {until_iso}")
        else:
            since_iso = read_last_run_iso()
            cutoff = datetime.now(timezone.utc) - timedelta(seconds=REVISION_SETTLE_SECONDS)
            until_iso = _format_utc_iso(cutoff)

        if _parse_iso_timestamp(until_iso) <= _parse_iso_timestamp(since_iso):
            logging.info("No settled reporting interval is available yet.")
            return

        logging.info(f"Querying changes after {since_iso} through {until_iso}")
        if EXCLUDED_USERS:
            logging.info(f"Excluding users: {', '.join(sorted(EXCLUDED_USERS))}")
        if HIDE_BOT_EDITS:
            logging.info("Bot edits will be hidden.")

        groups, order = parse_page_list(PAGE_LIST_FILE)
        group_payloads = _collect_group_payloads(
            session, groups, order, since_iso, until_iso)
        plan = build_report_plan(order, group_payloads, since_iso, until_iso)

        if pending:
            if plan is None:
                raise PendingReportError(
                    "Pending report regenerated with no revisions; refusing to discard it")
            plan = merge_pending_state(plan, pending)
        elif plan is None:
            logging.info("No new changes; keeping last_run unchanged.")
            return

        if not TG_BOT_TOKEN or not TG_CHAT_ID:
            raise PendingReportError("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing")
        if any(not part.get("url") for part in plan["parts"]) and not TELEGRAPH_ACCESS_TOKEN:
            raise TelegraphPublishError("TELEGRAPH_ACCESS_TOKEN is missing")
        preflight_telegram_notification(plan)

        # Persist the deterministic plan before the first external write. The
        # workflow commits this outbox even when monitor.py exits unsuccessfully.
        state = pending_state_from_plan(plan)
        save_pending_report(state)
        for number, part in enumerate(plan["parts"], start=1):
            if part.get("url"):
                logging.info(
                    f"Reusing Telegraph article {number}/{len(plan['parts'])}: {part['url']}")
                continue
            logging.info(f"Publishing Telegraph article {number}/{len(plan['parts'])}")
            part["url"] = create_telegraph_page(
                session, part["title"], part["content"])
            state = pending_state_from_plan(plan)
            save_pending_report(state)
            logging.info(f"Published Telegraph article {number}: {part['url']}")

        state = pending_state_from_plan(plan)
        if state["status"] != "ready":
            raise PendingReportError("Telegraph report did not reach ready state")
        save_pending_report(state)
        _notify_ready_report(session, state)
    except (RevisionFetchError, TelegraphPublishError, PendingReportError) as e:
        logging.error(str(e))
        logging.error("Aborting without advancing last_run.txt")
        sys.exit(1)


if __name__ == "__main__":
    main()
