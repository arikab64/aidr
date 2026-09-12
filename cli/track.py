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
        description="Manage tracked PIDs via the aidr monitor daemon socket."
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
        "-a",
        "--add",
        type=int,
        nargs="+",
        metavar="PID",
        help="Register PID(s) to track",
    )
    action_group.add_argument(
        "-d",
        "--delete",
        type=int,
        nargs="+",
        metavar="PID",
        help="Delete PID(s) from tracking",
    )
    action_group.add_argument(
        "--clean",
        action="store_true",
        help="Untrack all processes",
    )
    action_group.add_argument(
        "-l",
        "--list-tasks",
        action="store_true",
        help="List all tasks via the daemon's BPF task iterator",
    )

    action_group.add_argument(
        "-t", "--tree",
        type=int,
        metavar="PID",
        help="Mark every task under PID in the kernel and print the tree",
    )

    args = parser.parse_args()
    sock_path = Path(args.socket)

    commands = []
    if args.add:
        for pid in args.add:
            commands.append({"cmd": "track", "pid": pid})
    elif args.delete:
        for pid in args.delete:
            commands.append({"cmd": "untrack", "pid": pid})
    elif args.clean:
        commands.append({"cmd": "untrack_all"})
    elif args.list_tasks:
        commands.append({"cmd": "list_tasks"})
    elif args.tree:
        commands.append({"cmd": "tree", "pid": args.tree})

    has_error = False
    for cmd in commands:
        try:
            resp = send_command(sock_path, cmd)
            status = resp.get("status")
            if status == "ok":
                msg = resp.get("message", "ok")
                if cmd["cmd"] == "list_tasks" or cmd["cmd"] == "tree":
                    print(msg, end="")
                else:
                    print(f"[OK] {msg}")
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
