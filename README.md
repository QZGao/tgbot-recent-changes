# tgbot-recent-changes

A daily watcher for recent changes to selected Wikimedia pages. It publishes the
complete report to Telegraph and sends one Telegram notification containing links
to every report article.

## Behavior

- Pages are grouped in `page_list.txt` under `#` headings.
- Revisions by configured excluded users and detected bots are omitted.
- Each successful run queries through a two-minute safety cutoff, publishes an
  immutable Telegraph report, and advances `last_run.txt` only after Telegram
  delivery. The delayed cutoff prevents overlap duplicates at the watermark.
- Reports larger than Telegraph's per-article limit are divided into multiple
  articles. All article links are included in the same Telegram message.
- `pending_report.json` is a durable delivery outbox. GitHub Actions commits it
  after a partial failure so a later run can reuse published articles and retry
  delivery without advancing the reporting watermark.

Telegraph articles are public web pages. Do not include private information in
the generated report.

## GitHub Actions secrets

Configure these repository secrets:

- `TELEGRAM_BOT_TOKEN`: Telegram Bot API token.
- `TELEGRAM_CHAT_ID`: destination chat, group, or channel identifier.
- `TELEGRAPH_ACCESS_TOKEN`: access token for a Telegraph account created through
  the Telegraph API.

The scheduled workflow runs the unit tests before executing the watcher. It also
serializes scheduled and manually dispatched runs to protect the reporting and
delivery state from concurrent updates.
