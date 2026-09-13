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


def get_starttime(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat", "r") as f:
            stat_str = f.read()
            # The process name is enclosed in parentheses and may contain spaces.
            # Find the last ')' to safely split the rest of the fields.
            rparen_idx = stat_str.rfind(')')
            if rparen_idx != -1:
                # The substring after ') ' contains fields starting from index 2 (state)
                rest = stat_str[rparen_idx + 2:]
                parts = rest.split()
                # starttime is the 22nd field overall (index 21).
                # Since we skipped the first 2 fields (pid, comm), it is at index 19 of `rest`.
                return int(parts[19])
    except Exception:
        pass
    return 0


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
        nargs=2,
        metavar=("PID", "WORKLOAD_ID"),
        help="Track every task under PID and assign it WORKLOAD_ID",
    )
    action_group.add_argument(
        "-u",
        "--untrack",
        type=int,
        nargs="+",
        metavar="WORKLOAD_ID",
        help="Untrack every task associated with WORKLOAD_ID(s)",
    )

    args = parser.parse_args()
    sock_path = Path(args.socket)

    commands = []
    if args.tree:
        pid, workload_id = args.tree
        starttime = get_starttime(pid)
        commands.append({
            "cmd": "tree",
            "pid": pid,
            "starttime": starttime,
            "workload_id": workload_id
        })
    elif args.untrack:
        for w_id in args.untrack:
            commands.append({"cmd": "untrack", "workload_id": w_id})

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
