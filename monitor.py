#!/usr/bin/env python3
import html
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, unquote

import requests

# --- Config ---
USER_AGENT = "WikimediaDailyWatcher/1.0 (GitHub Actions) contact: N/A"
LAST_RUN_FILE = "last_run.txt"
PAGE_LIST_FILE = "page_list.txt"
TELEGRAM_API = "https://api.telegram.org"
EXCLUDED_USERS = {'SuperGrey'}
HIDE_BOT_EDITS = True

# Read secrets from env (set these in GitHub Actions Secrets)
TG_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")


logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


def read_last_run_iso():
    if not os.path.exists(LAST_RUN_FILE):
        # default to 7 days back on first run
        return (datetime.now(timezone.utc) - timedelta(days=7)).isoformat(timespec="seconds").replace("+00:00", "Z")
    s = open(LAST_RUN_FILE, "r", encoding="utf-8").read().strip()
    # tolerate plain timestamps without Z
    if s.endswith("Z"):
        return s
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
        return dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    except Exception:
        # fallback: treat as UTC with no tz
        try:
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt.isoformat(timespec="seconds").replace("+00:00", "Z")
        except Exception:
            logging.warning("Invalid last_run.txt; defaulting to 24h ago.")
            return (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")


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


def fetch_revisions_since(session, domain, title, since_iso, now_iso, overlap_seconds=120):
    """
    Fetch page revisions strictly after last run, up to now, in chronological order.
    Uses rvdir=newer so the list goes oldest -> newest.

    We expand the window slightly backwards by `overlap_seconds` to avoid
    missing edits that occur exactly at since_iso due to boundary semantics.

    Returns list of revisions after applying exclusion filters.
    """
    endpoint = api_endpoint_for_domain(domain)

    # Apply a slight overlap to avoid boundary misses
    try:
        since_dt = datetime.fromisoformat(since_iso.replace("Z", "+00:00"))
    except Exception:
        since_dt = datetime.now(timezone.utc) - timedelta(days=1)
    since_safe_iso = (since_dt - timedelta(seconds=overlap_seconds)).astimezone(timezone.utc) \
                        .isoformat(timespec="seconds").replace("+00:00", "Z")

    params = {
        "action": "query",
        "format": "json",
        "prop": "revisions",
        "titles": title,
        "redirects": "1",
        "rvprop": "ids|timestamp|user|comment|size|flags|tags|sha1",
        "rvdir": "newer",          # chronological
        "rvstart": since_safe_iso, # EARLIEST bound (start at/after this)
        "rvend": now_iso,          # LATEST bound (up to this)
        "rvlimit": "50",
    }

    all_revs = []
    tries = 0
    data = None  # initialize for linter
    while True:
        try:
            r = session.get(endpoint, params=params, timeout=30)
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            tries += 1
            if tries <= 3:
                sleep = 2 ** tries
                logging.warning(f"{domain} {title}: API error {e}; retrying in {sleep}s...")
                time.sleep(sleep)
                continue
            logging.error(f"{domain} {title}: Failed after retries.")
            return []

        pages = data.get("query", {}).get("pages", {}) if data else {}
        for _, p in pages.items():
            revs = p.get("revisions", [])
            all_revs.extend(revs)

        cont = data.get("continue", {}).get("rvcontinue") if data else None
        if cont:
            params["rvcontinue"] = cont
        else:
            break

    # Apply filtering (excluded users & bot edits)
    filtered_revs = _filter_revisions(all_revs)
    logging.info(f"{domain} {title}: {len(filtered_revs)} new rev(s) (raw: {len(all_revs)}) between {since_iso} and {now_iso}")
    return filtered_revs


def build_diff_url(domain, revid, parentid):
    if parentid is None:
        return f"https://{domain}/w/index.php?diff={revid}"
    return f"https://{domain}/w/index.php?diff={revid}&oldid={parentid}"


def sanitize_for_telegram_html(s):
    # Telegram HTML supports a subset; escape everything dangerous.
    return html.escape(s, quote=False)


def format_group_message(group_name, grouped_pages):
    """
    grouped_pages: list of { 'domain', 'title', 'url', 'revisions': [ ... ] }
    Returns str for Telegram HTML.
    """
    parts = []
    parts.append(f"<b>{sanitize_for_telegram_html(group_name)}</b>")
    for page in grouped_pages:
        if not page.get("revisions"):
            continue
        domain = page["domain"]
        title = page["title"]
        url = page["url"]
        safe_title = sanitize_for_telegram_html(title)
        parts.append(f"\n<a href=\"{html.escape(url)}\">{safe_title}</a>")

        for rev in page["revisions"]:
            ts = rev.get("timestamp", "")
            user = rev.get("user", "")
            comment = rev.get("comment", "") or ""
            revid = rev.get("revid")
            parentid = rev.get("parentid", None)
            diff_url = build_diff_url(domain, revid, parentid)
            safe_user = sanitize_for_telegram_html(user)
            safe_comment = sanitize_for_telegram_html(comment)

            # Example line: • 2025-09-25T00:12:34Z — UserName: edit summary (diff)
            parts.append(
                f"• <code>{ts}</code> — <b>{safe_user}</b>: {safe_comment} (<a href=\"{html.escape(diff_url)}\">diff</a>)")
    return "\n".join(parts)


def send_telegram_message(session, text):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        logging.error("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing.")
        return False
    endpoint = f"{TELEGRAM_API}/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TG_CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    tries = 0
    while True:
        try:
            r = session.post(endpoint, json=payload, timeout=30)
            if r.status_code == 429:
                # rate limited
                retry_after = r.json().get("parameters", {}).get("retry_after", 3)
                time.sleep(int(retry_after) + 1)
                continue
            r.raise_for_status()
            return True
        except Exception as e:
            tries += 1
            if tries <= 3:
                sleep = 2 ** tries
                logging.warning(f"Telegram send error {e}; retry in {sleep}s")
                time.sleep(sleep)
                continue
            logging.error("Telegram send failed after retries.")
            return False


def main():
    last_run_iso = read_last_run_iso()
    run_start_iso = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    logging.info(f"Querying changes from {last_run_iso} to {run_start_iso}")

    if EXCLUDED_USERS:
        logging.info(f"Excluding users: {', '.join(sorted(EXCLUDED_USERS))}")
    if HIDE_BOT_EDITS:
        logging.info("Bot edits will be hidden.")

    groups, order = parse_page_list(PAGE_LIST_FILE)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    # Collect per group
    any_changes = False
    group_payloads = {}  # group -> list of page dicts with revisions
    for group_name in order:
        pages = groups.get(group_name, [])
        prepared = []
        for page in pages:
            revs = fetch_revisions_since(session, page["domain"], page["title"], last_run_iso, run_start_iso)
            if revs:
                any_changes = True
            prepared.append({**page, "revisions": revs})
        group_payloads[group_name] = prepared

    # Send Telegram messages per group, only if any of its pages had changes
    for group_name in order:
        pages = group_payloads[group_name]
        if not any(p.get("revisions") for p in pages):
            continue
        text = format_group_message(group_name, pages)
        ok = send_telegram_message(session, text)
        if not ok:
            logging.error(f"Failed to send Telegram message for group '{group_name}'")

    if any_changes:
        with open(LAST_RUN_FILE, "w", encoding="utf-8") as f:
            f.write(run_start_iso + "\n")
        logging.info(f"Updated {LAST_RUN_FILE} -> {run_start_iso}")
    else:
        logging.info("No new changes; keeping last_run unchanged.")


if __name__ == "__main__":
    main()
