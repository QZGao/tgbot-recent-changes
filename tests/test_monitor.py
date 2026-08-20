import json
import os
import tempfile
import unittest
from unittest import mock

import requests

import monitor


class FakeResponse:
    def __init__(self, payload=None, status_code=200, headers=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            error = requests.exceptions.HTTPError(f"HTTP {self.status_code}")
            error.response = self
            raise error


class FakeSession:
    def __init__(self, get_responses=None, post_responses=None):
        self.get_responses = list(get_responses or [])
        self.post_responses = list(post_responses or [])
        self.get_calls = []
        self.post_calls = []
        self.headers = {}

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        response = self.get_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        response = self.post_responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def make_revision(revid, timestamp, comment="edit", user="Editor"):
    return {
        "revid": revid,
        "parentid": revid - 1,
        "timestamp": timestamp,
        "user": user,
        "comment": comment,
        "tags": [],
    }


def make_payloads(revisions):
    page = {
        "domain": "en.wikipedia.org",
        "title": "Example",
        "url": "https://en.wikipedia.org/wiki/Example",
        "revisions": revisions,
    }
    return ["Group"], {"Group": [page]}


def make_ready_state(part_count=1):
    revisions = [make_revision(100 + number, "2026-08-20T00:10:00Z")
                 for number in range(part_count)]
    order, payloads = make_payloads(revisions)
    plan = monitor.build_report_plan(
        order, payloads, "2026-08-19T00:00:00Z", "2026-08-20T00:00:00Z")
    if part_count > 1 and len(plan["parts"]) == 1:
        # Notification tests need multiple links, not real pagination.
        original = plan["parts"][0]
        plan["parts"] = []
        for number in range(part_count):
            plan["parts"].append({
                **original,
                "title": f"Part {number + 1}",
                "content_sha256": f"{number + 1:064x}",
            })
    for number, part in enumerate(plan["parts"], start=1):
        part["url"] = f"https://telegra.ph/report-{number}"
    return monitor.pending_state_from_plan(plan)


class RevisionFetchTests(unittest.TestCase):
    def test_fetch_enforces_strict_lower_bound_and_deduplicates(self):
        payload = {
            "query": {
                "pages": {
                    "1": {
                        "revisions": [
                            make_revision(1, "2026-08-20T00:00:00Z"),
                            make_revision(2, "2026-08-20T00:00:01Z"),
                            make_revision(2, "2026-08-20T00:00:01Z"),
                            make_revision(3, "2026-08-20T01:00:00Z"),
                            make_revision(4, "2026-08-20T01:00:01Z"),
                        ]
                    }
                }
            }
        }
        session = FakeSession(get_responses=[FakeResponse(payload)])
        with mock.patch.object(monitor, "EXCLUDED_USERS", set()), \
                mock.patch.object(monitor, "HIDE_BOT_EDITS", False):
            revisions = monitor.fetch_revisions_since(
                session,
                "en.wikipedia.org",
                "Example",
                "2026-08-20T00:00:00Z",
                "2026-08-20T01:00:00Z",
                max_retries=0,
                request_delay_seconds=0,
            )

        self.assertEqual([revision["revid"] for revision in revisions], [2, 3])
        params = session.get_calls[0][1]["params"]
        self.assertEqual(params["rvstart"], "2026-08-20T00:00:00Z")
        self.assertEqual(params["rvend"], "2026-08-20T01:00:00Z")

    def test_api_error_is_not_treated_as_no_changes(self):
        session = FakeSession(get_responses=[FakeResponse({
            "error": {"code": "ratelimited"}
        })])
        with self.assertRaises(monitor.RevisionFetchError):
            monitor.fetch_revisions_since(
                session,
                "en.wikipedia.org",
                "Example",
                "2026-08-20T00:00:00Z",
                "2026-08-20T01:00:00Z",
                max_retries=0,
                request_delay_seconds=0,
            )

    def test_http_failure_is_not_treated_as_no_changes(self):
        session = FakeSession(get_responses=[FakeResponse({}, status_code=503)])
        with self.assertRaises(monitor.RevisionFetchError):
            monitor.fetch_revisions_since(
                session,
                "en.wikipedia.org",
                "Example",
                "2026-08-20T00:00:00Z",
                "2026-08-20T01:00:00Z",
                max_retries=0,
                request_delay_seconds=0,
            )

    def test_malformed_success_is_not_treated_as_no_changes(self):
        session = FakeSession(get_responses=[FakeResponse({"batchcomplete": True})])
        with self.assertRaises(monitor.RevisionFetchError):
            monitor.fetch_revisions_since(
                session,
                "en.wikipedia.org",
                "Example",
                "2026-08-20T00:00:00Z",
                "2026-08-20T01:00:00Z",
                max_retries=0,
                request_delay_seconds=0,
            )

    def test_mediawiki_request_is_paced(self):
        session = FakeSession(get_responses=[
            FakeResponse({
                "query": {"pages": {"1": {}}},
                "continue": {"rvcontinue": "next-page"},
            }),
            FakeResponse({"query": {"pages": {"1": {}}}}),
        ])
        with mock.patch.object(monitor.time, "sleep") as sleep:
            monitor.fetch_revisions_since(
                session,
                "en.wikipedia.org",
                "Example",
                "2026-08-20T00:00:00Z",
                "2026-08-20T01:00:00Z",
                max_retries=0,
            )

        self.assertEqual(sleep.call_count, 2)
        sleep.assert_has_calls([
            mock.call(monitor.MEDIAWIKI_REQUEST_DELAY_SECONDS),
            mock.call(monitor.MEDIAWIKI_REQUEST_DELAY_SECONDS),
        ])


class TelegraphRenderingTests(unittest.TestCase):
    def test_unicode_content_is_serialized_as_utf8(self):
        serialized = monitor.serialize_telegraph_content([
            {"tag": "p", "children": ["測試"]}
        ])
        self.assertIn("測試", serialized)
        self.assertNotIn("\\u6e2c", serialized)

    def test_large_report_is_split_without_dropping_revisions(self):
        revisions = [
            make_revision(number, f"2026-08-20T00:{number:02d}:00Z", "x" * 600)
            for number in range(1, 7)
        ]
        order, payloads = make_payloads(revisions)
        plan = monitor.build_report_plan(
            order,
            payloads,
            "2026-08-19T00:00:00Z",
            "2026-08-20T01:00:00Z",
            max_bytes=1800,
        )

        self.assertGreater(len(plan["parts"]), 1)
        combined = "\n".join(part["content_json"] for part in plan["parts"])
        for revision in revisions:
            self.assertEqual(combined.count(f"diff={revision['revid']}&"), 1)
        for part in plan["parts"]:
            self.assertLessEqual(
                len(part["content_json"].encode("utf-8")), 1800)

    def test_single_oversized_revision_fails_before_publish(self):
        order, payloads = make_payloads([
            make_revision(1, "2026-08-20T00:01:00Z", "x" * 5000)
        ])
        with self.assertRaises(monitor.TelegraphPublishError):
            monitor.build_report_plan(
                order,
                payloads,
                "2026-08-19T00:00:00Z",
                "2026-08-20T01:00:00Z",
                max_bytes=1000,
            )

    def test_create_page_posts_serialized_content_without_token_in_url(self):
        session = FakeSession(post_responses=[
            FakeResponse({
                "ok": True,
                "result": {"total_count": 0, "pages": []},
            }),
            FakeResponse({
                "ok": True,
                "result": {"url": "https://telegra.ph/report-1"},
            }),
        ])
        content = [{"tag": "p", "children": ["hello"]}]
        with mock.patch.object(monitor, "TELEGRAPH_ACCESS_TOKEN", "secret-token"):
            url = monitor.create_telegraph_page(session, "Report", content)

        self.assertEqual(url, "https://telegra.ph/report-1")
        endpoint, kwargs = session.post_calls[1]
        self.assertNotIn("secret-token", endpoint)
        self.assertEqual(json.loads(kwargs["data"]["content"]), content)

    def test_create_page_recovers_page_created_before_state_was_saved(self):
        content = [{"tag": "p", "children": ["hello"]}]
        session = FakeSession(post_responses=[
            FakeResponse({
                "ok": True,
                "result": {
                    "total_count": 1,
                    "pages": [{
                        "title": "Report",
                        "path": "Report-08-20",
                        "url": "https://telegra.ph/Report-08-20",
                    }],
                },
            }),
            FakeResponse({
                "ok": True,
                "result": {
                    "url": "https://telegra.ph/Report-08-20",
                    "content": content,
                },
            }),
        ])
        with mock.patch.object(monitor, "TELEGRAPH_ACCESS_TOKEN", "secret-token"):
            url = monitor.create_telegraph_page(session, "Report", content)

        self.assertEqual(url, "https://telegra.ph/Report-08-20")
        self.assertEqual(len(session.post_calls), 2)


class DeliveryStateTests(unittest.TestCase):
    def test_invalid_watermark_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "last_run.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write("not-a-timestamp\n")
            with self.assertRaises(monitor.PendingReportError):
                monitor.read_last_run_iso(path)

    def test_pending_state_round_trip_and_clear(self):
        state = make_ready_state()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "pending.json")
            monitor.save_pending_report(state, path)
            self.assertEqual(monitor.load_pending_report(path), state)
            monitor.save_pending_report({}, path)
            self.assertIsNone(monitor.load_pending_report(path))

    def test_regenerated_plan_must_match_pending_hashes(self):
        order, payloads = make_payloads([
            make_revision(1, "2026-08-20T00:01:00Z")
        ])
        plan = monitor.build_report_plan(
            order, payloads, "2026-08-19T00:00:00Z", "2026-08-20T01:00:00Z")
        state = monitor.pending_state_from_plan(plan)
        state["parts"][0]["content_sha256"] = "f" * 64
        with self.assertRaises(monitor.PendingReportError):
            monitor.merge_pending_state(plan, state)

    def test_one_notification_contains_every_article_link(self):
        state = make_ready_state(part_count=3)
        message = monitor.build_telegram_notification(state)
        for number in range(1, 4):
            self.assertIn(f"https://telegra.ph/report-{number}", message)
        self.assertEqual(message.count("<a href="), 3)

    def test_notification_limit_fails_closed(self):
        with self.assertRaises(monitor.PendingReportError):
            monitor.build_telegram_notification(make_ready_state(), max_chars=20)

    def test_pending_state_rejects_non_telegraph_url(self):
        state = make_ready_state()
        state["parts"][0]["url"] = "https://example.com/report"
        with self.assertRaises(monitor.PendingReportError):
            monitor.build_telegram_notification(state)

    def test_excessive_part_count_fails_before_publication(self):
        order, payloads = make_payloads([
            make_revision(1, "2026-08-20T00:01:00Z")
        ])
        plan = monitor.build_report_plan(
            order, payloads, "2026-08-19T00:00:00Z", "2026-08-20T01:00:00Z")
        original = plan["parts"][0]
        plan["parts"] = [{
            **original,
            "title": f"Part {number}",
            "content_sha256": f"{number:064x}",
            "url": None,
        } for number in range(1, 401)]
        with self.assertRaises(monitor.PendingReportError):
            monitor.preflight_telegram_notification(plan)

    def test_telegram_send_uses_link_preview_options(self):
        session = FakeSession(post_responses=[FakeResponse({
            "ok": True,
            "result": {"message_id": 1},
        })])
        with mock.patch.object(monitor, "TG_BOT_TOKEN", "bot-token"), \
                mock.patch.object(monitor, "TG_CHAT_ID", "chat-id"):
            self.assertTrue(monitor.send_telegram_message(session, "hello"))

        _, kwargs = session.post_calls[0]
        payload = kwargs["json"]
        self.assertEqual(payload["link_preview_options"], {"is_disabled": False})
        self.assertNotIn("disable_web_page_preview", payload)


class MainTransactionTests(unittest.TestCase):
    def _run_in_directory(self, directory, callback):
        previous = os.getcwd()
        os.chdir(directory)
        try:
            return callback()
        finally:
            os.chdir(previous)

    def test_failed_notification_persists_ready_outbox_without_advancing(self):
        order, payloads = make_payloads([
            make_revision(1, "2026-08-20T00:01:00Z")
        ])

        def run():
            with open("last_run.txt", "w", encoding="utf-8") as f:
                f.write("2026-08-19T00:00:00Z\n")
            with open("pending_report.json", "w", encoding="utf-8") as f:
                f.write("{}\n")
            with mock.patch.object(monitor.requests, "Session", return_value=FakeSession()), \
                    mock.patch.object(monitor, "parse_page_list", return_value=({}, order)), \
                    mock.patch.object(monitor, "_collect_group_payloads", return_value=payloads), \
                    mock.patch.object(monitor, "create_telegraph_page",
                                      return_value="https://telegra.ph/report-1"), \
                    mock.patch.object(monitor, "send_telegram_message", return_value=False), \
                    mock.patch.object(monitor, "TG_BOT_TOKEN", "bot-token"), \
                    mock.patch.object(monitor, "TG_CHAT_ID", "chat-id"), \
                    mock.patch.object(monitor, "TELEGRAPH_ACCESS_TOKEN", "telegraph-token"):
                with self.assertRaises(SystemExit):
                    monitor.main()

            with open("last_run.txt", "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), "2026-08-19T00:00:00Z")
            state = monitor.load_pending_report("pending_report.json")
            self.assertEqual(state["status"], "ready")
            self.assertEqual(state["parts"][0]["url"], "https://telegra.ph/report-1")

        with tempfile.TemporaryDirectory() as directory:
            self._run_in_directory(directory, run)

    def test_ready_outbox_retries_without_refetching_then_advances(self):
        state = make_ready_state()

        def run():
            with open("last_run.txt", "w", encoding="utf-8") as f:
                f.write("2026-08-19T00:00:00Z\n")
            monitor.save_pending_report(state, "pending_report.json")
            with mock.patch.object(monitor.requests, "Session", return_value=FakeSession()), \
                    mock.patch.object(monitor, "_collect_group_payloads") as collect, \
                    mock.patch.object(monitor, "send_telegram_message", return_value=True):
                monitor.main()

            collect.assert_not_called()
            with open("last_run.txt", "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), state["until"])
            self.assertIsNone(monitor.load_pending_report("pending_report.json"))

        with tempfile.TemporaryDirectory() as directory:
            self._run_in_directory(directory, run)

    def test_fetch_failure_leaves_watermark_and_empty_outbox_unchanged(self):
        def run():
            with open("last_run.txt", "w", encoding="utf-8") as f:
                f.write("2026-08-19T00:00:00Z\n")
            with open("pending_report.json", "w", encoding="utf-8") as f:
                f.write("{}\n")
            with mock.patch.object(monitor.requests, "Session", return_value=FakeSession()), \
                    mock.patch.object(monitor, "parse_page_list", return_value=({}, [])), \
                    mock.patch.object(
                        monitor, "_collect_group_payloads",
                        side_effect=monitor.RevisionFetchError("fetch failed")):
                with self.assertRaises(SystemExit):
                    monitor.main()

            with open("last_run.txt", "r", encoding="utf-8") as f:
                self.assertEqual(f.read().strip(), "2026-08-19T00:00:00Z")
            self.assertIsNone(monitor.load_pending_report("pending_report.json"))

        with tempfile.TemporaryDirectory() as directory:
            self._run_in_directory(directory, run)


if __name__ == "__main__":
    unittest.main()
