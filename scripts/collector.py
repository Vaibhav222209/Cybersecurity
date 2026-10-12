#!/usr/bin/env python3
"""Forward a local JSONL log file to AEGIS without third-party dependencies."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request


FIELDS = {"timestamp", "sourceIp", "assetId", "assetName", "severity", "category", "message", "domain", "hash"}
STOP = threading.Event()


class DeliveryError(Exception):
    """An event was not acknowledged by the server."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        # A collector must not forward its bearer token to a redirected host.
        return None


def report(message: str) -> None:
    print(f"collector: {message}", file=sys.stderr, flush=True)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True, type=Path, help="local JSONL log file")
    parser.add_argument("--url", default="http://127.0.0.1:3001/api/ingest", help="AEGIS ingestion URL")
    parser.add_argument("--token", default=os.environ.get("INGEST_TOKEN"), help="ingestion token; prefer INGEST_TOKEN environment variable")
    parser.add_argument("--from-start", action="store_true", help="import existing lines, overriding any checkpoint")
    parser.add_argument("--once", action="store_true", help="read available lines and exit")
    parser.add_argument("--checkpoint", type=Path, help="optional durable offset file for restart recovery")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="tail polling interval in seconds (default: 0.5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds (default: 10)")
    parser.add_argument("--retries", type=int, default=3, help="additional attempts for temporary HTTP failures (default: 3)")
    args = parser.parse_args()
    url = urllib.parse.urlsplit(args.url)
    if url.scheme not in {"http", "https"} or not url.hostname or url.username or url.password:
        parser.error("--url must be an HTTP(S) URL without embedded credentials")
    if args.poll_interval <= 0 or args.timeout <= 0 or not 0 <= args.retries <= 10:
        parser.error("interval and timeout must be positive; retries must be between 0 and 10")
    if args.checkpoint and args.checkpoint.resolve() == args.file.resolve():
        parser.error("checkpoint must be different from the input file")
    return args


def decode_event(line: bytes) -> dict:
    def reject_constant(value: str) -> None:
        raise ValueError("non-finite JSON number")

    value = json.loads(line.decode("utf-8"), parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("event must be a JSON object")
    event = {key: value[key] for key in FIELDS if key in value}
    if not isinstance(event.get("message"), str) or not event["message"].strip():
        raise ValueError("message must be a nonempty string")
    if any(not isinstance(item, str) for item in event.values()):
        raise ValueError("supported event fields must be strings")
    return event


def deliver(event: dict, args: argparse.Namespace) -> None:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    request = urllib.request.Request(args.url, data=json.dumps(event).encode("utf-8"), headers=headers, method="POST")
    opener = urllib.request.build_opener(NoRedirect())
    for attempt in range(args.retries + 1):
        if STOP.is_set():
            raise DeliveryError("stopped before acknowledgement")
        try:
            # urllib verifies HTTPS certificates using the platform trust store.
            with opener.open(request, timeout=args.timeout) as response:
                response.read(4096)
                if 200 <= response.status < 300:
                    return
                reason = f"HTTP {response.status}"
                retryable = response.status == 429 or response.status >= 500
        except urllib.error.HTTPError as error:
            reason = f"HTTP {error.code}"
            retryable = error.code in {408, 429} or error.code >= 500
            error.close()
        except (urllib.error.URLError, TimeoutError, OSError):
            # Do not log exception text: URLs, headers and proxy details can contain secrets.
            reason = "connection or TLS failure"
            retryable = True
        if not retryable or attempt == args.retries:
            raise DeliveryError(f"delivery failed ({reason}); event was not acknowledged")
        delay = min(2**attempt, 16)
        report(f"temporary delivery failure ({reason}); retry {attempt + 1}/{args.retries} in {delay}s")
        if STOP.wait(delay):
            raise DeliveryError("stopped before acknowledgement")


def checkpoint(args: argparse.Namespace, stream) -> None:
    if args.checkpoint is None:
        return
    stat = os.fstat(stream.fileno())
    value = {"file": str(args.file.resolve()), "device": stat.st_dev, "inode": stat.st_ino, "offset": stream.tell()}
    args.checkpoint.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.checkpoint.with_name(args.checkpoint.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(args.checkpoint)


def initial_offset(args: argparse.Namespace, stream) -> int:
    stat = os.fstat(stream.fileno())
    if args.from_start:
        return 0
    if args.checkpoint and args.checkpoint.exists():
        try:
            saved = json.loads(args.checkpoint.read_text(encoding="utf-8"))
            offset = saved.get("offset")
            if (saved.get("file") == str(args.file.resolve()) and saved.get("device") == stat.st_dev
                    and saved.get("inode") == stat.st_ino and isinstance(offset, int) and 0 <= offset <= stat.st_size):
                report("resuming acknowledged checkpoint")
                return offset
            report("checkpoint belongs to a replaced or truncated file; reading current file from its beginning")
            return 0
        except (OSError, ValueError, AttributeError):
            raise ValueError("checkpoint is unreadable or invalid; choose a new checkpoint or use --from-start") from None
    return stat.st_size


def replacement(args: argparse.Namespace, stream):
    """Follow rename rotation and truncation, retaining the old stream while its path is absent."""
    try:
        path_stat = args.file.stat()
    except FileNotFoundError:
        return stream
    open_stat = os.fstat(stream.fileno())
    if (path_stat.st_dev, path_stat.st_ino) != (open_stat.st_dev, open_stat.st_ino):
        new_stream = args.file.open("rb")
        stream.close()
        report("log rotation detected; following replacement from its beginning")
        checkpoint(args, new_stream)
        return new_stream
    if path_stat.st_size < stream.tell():
        stream.seek(0)
        report("log truncation detected; reading from its beginning")
        checkpoint(args, stream)
    return stream


def run(args: argparse.Namespace) -> int:
    sent = skipped = 0
    stream = None
    try:
        stream = args.file.open("rb")
        stream.seek(initial_offset(args, stream))
        checkpoint(args, stream)
        report("reading existing events" if args.from_start else "watching appended events")
        while not STOP.is_set():
            offset = stream.tell()
            line = stream.readline()
            if not line:
                if args.once:
                    break
                stream = replacement(args, stream)
                STOP.wait(args.poll_interval)
                continue
            if not line.endswith(b"\n") and not args.once:
                # An actively written line may contain only part of a JSON object.
                stream.seek(offset)
                stream = replacement(args, stream)
                STOP.wait(args.poll_interval)
                continue
            if not line.strip():
                checkpoint(args, stream)
                continue
            try:
                event = decode_event(line)
            except (UnicodeError, ValueError):
                skipped += 1
                report(f"skipping invalid JSON event at byte {offset}; supported fields must be strings and message is required")
                checkpoint(args, stream)
                continue
            try:
                deliver(event, args)
            except DeliveryError:
                stream.seek(offset)
                raise
            sent += 1
            checkpoint(args, stream)
            if sent == 1 or sent % 25 == 0:
                report(f"acknowledged {sent} event(s)")
        report(f"stopped: {sent} acknowledged, {skipped} invalid event(s) skipped")
        return 0
    except DeliveryError as error:
        report(str(error))
        if args.checkpoint:
            report("restart with the same --checkpoint to retry the unacknowledged event")
        else:
            report("use --from-start to replay, or configure --checkpoint for durable restart recovery")
        return 0 if STOP.is_set() else 1
    except (OSError, ValueError):
        report("unable to read the input or maintain the checkpoint; verify paths and file permissions")
        return 1
    finally:
        if stream:
            stream.close()


def main() -> int:
    args = arguments()
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
