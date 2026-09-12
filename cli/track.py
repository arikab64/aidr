#!/usr/bin/env python3
"""CLI utility to send tracking commands to the aidr monitoring daemon."""

import argparse
import json
import socket
import sys
from pathlib import Path

DEFAULT_SOCKET_PATH = Path("/run/aidr/mon.sock")


def send_command(sock_path: Path, payload: dict) -> dict:
    if not sock_path.exists():
        raise FileNotFoundError(
            f"Socket '{sock_path}' does not exist. Is the 'mon' daemon running?"
        )

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(sock_path))
        data = json.dumps(payload) + "\n"
        client.sendall(data.encode("utf-8"))

        buffer = ""
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            buffer += chunk.decode("utf-8")
            if "\n" in buffer:
                break

        line = buffer.strip().split("\n")[0]
        if not line:
            raise RuntimeError("Received empty response from monitor daemon")
        return json.loads(line)
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Track or untrack process trees via the aidr monitor daemon socket."
    )
    parser.add_argument(
        "-s",
        "--socket",
        type=str,
        default=str(DEFAULT_SOCKET_PATH),
        help="Path to daemon Unix domain socket (default: %(default)s)",
    )

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "-t",
        "--tree",
        type=int,
        nargs="+",
        metavar="PID",
        help="Track every task under PID(s) in the kernel and print the tree",
    )
    action_group.add_argument(
        "-u",
        "--untrack",
        type=int,
        nargs="+",
        metavar="PID",
        help="Untrack every task rooted at PID(s) and print what was removed",
    )

    args = parser.parse_args()
    sock_path = Path(args.socket)

    commands = []
    if args.tree:
        for pid in args.tree:
            commands.append({"cmd": "tree", "pid": pid})
    elif args.untrack:
        for pid in args.untrack:
            commands.append({"cmd": "untrack", "pid": pid})

    has_error = False
    for cmd in commands:
        try:
            resp = send_command(sock_path, cmd)
            status = resp.get("status")
            if status == "ok":
                # Both commands return the iterator's table; print it as is.
                print(resp.get("message", ""), end="")
            else:
                err = resp.get("error", "unknown error")
                print(f"[ERROR] {err}", file=sys.stderr)
                has_error = True
        except Exception as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 1

    return 1 if has_error else 0


if __name__ == "__main__":
    sys.exit(main())
