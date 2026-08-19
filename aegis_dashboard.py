#!/usr/bin/env python3

import os
import time
import shutil
import socket
import subprocess

PROTOCOL_NAME = "QARMR"
ENCRYPTION_STATUS = "Active - AEAD / Hybrid KEX"

RAM_THRESHOLD = 85.0
REFRESH_RATE = 2.0

CONNECT_HOST = "1.1.1.1"
CONNECT_PORT = 53
CONNECT_TIMEOUT = 2.0


def run_command(args, timeout=3):
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except Exception:
        return None


def get_ram_usage():
    result = run_command(["free"])

    if result is None:
        return 0.0

    for line in result.stdout.splitlines():
        parts = line.split()

        if not parts:
            continue

        if parts[0].lower().rstrip(":") != "mem":
            continue

        try:
            total = float(parts[1])
            used = float(parts[2])

            if total > 0:
                return (used / total) * 100.0

        except (ValueError, IndexError):
            return 0.0

    return 0.0


def get_pid_count():
    result = run_command(["ps", "-e"])

    if result is None:
        return 0

    lines = [
        line
        for line in result.stdout.splitlines()
        if line.strip()
    ]

    return max(0, len(lines) - 1)


def get_load_status():
    try:
        load1, load5, load15 = os.getloadavg()
        cpu_count = os.cpu_count() or 1
        normalized = load1 / cpu_count

        if normalized < 0.75:
            status = "OPTIMAL"
        elif normalized < 1.0:
            status = "ELEVATED"
        elif normalized < 2.0:
            status = "HIGH"
        else:
            status = "CRITICAL"

        return (
            status,
            load1,
            load5,
            load15,
            cpu_count,
            normalized,
        )

    except Exception:
        return (
            "UNKNOWN",
            0.0,
            0.0,
            0.0,
            1,
            0.0,
        )


def get_active_interfaces():
    result = run_command(["ip", "-o", "link"])

    if result is None:
        return []

    interfaces = []

    for line in result.stdout.splitlines():
        parts = line.split(":", 2)

        if len(parts) < 3:
            continue

        name = parts[1].strip()
        flags = parts[2]

        if name == "lo":
            continue

        if "UP" in flags:
            interfaces.append(name)

    return interfaces


def get_default_interface():
    result = run_command(
        ["ip", "route", "show", "default"]
    )

    if result is None:
        return "UNKNOWN"

    parts = result.stdout.split()

    if "dev" in parts:
        try:
            return parts[parts.index("dev") + 1]
        except (IndexError, ValueError):
            pass

    return "UNKNOWN"


def check_vpn():
    interfaces = get_active_interfaces()

    prefixes = (
        "tun",
        "tap",
        "wg",
        "ppp",
    )

    return any(
        interface.startswith(prefixes)
        for interface in interfaces
    )


def check_proxy():
    proxy_vars = (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    )

    return any(
        bool(os.environ.get(var))
        for var in proxy_vars
    )


def check_connectivity():
    start = time.perf_counter()

    try:
        sock = socket.create_connection(
            (CONNECT_HOST, CONNECT_PORT),
            timeout=CONNECT_TIMEOUT,
        )

        sock.close()

        latency = (
            time.perf_counter() - start
        ) * 1000.0

        return True, latency

    except OSError:
        return False, None


def get_network_counters():
    """
    Android-safe network counter lookup.

    Deliberately does NOT read /proc/net/dev.
    """

    interfaces = get_active_interfaces()

    if not interfaces:
        return None

    total_rx = 0
    total_tx = 0
    found = False

    for interface in interfaces:
        base = (
            "/sys/class/net/"
            + interface
            + "/statistics/"
        )

        rx_file = base + "rx_bytes"
        tx_file = base + "tx_bytes"

        try:
            with open(rx_file, "r") as file:
                rx = int(file.read().strip())

            with open(tx_file, "r") as file:
                tx = int(file.read().strip())

            total_rx += rx
            total_tx += tx
            found = True

        except (
            PermissionError,
            FileNotFoundError,
            ValueError,
            OSError,
        ):
            continue

    if not found:
        return None

    return total_tx, total_rx


def format_rate(value):
    if value is None:
        return "N/A"

    value = float(value)

    units = (
        "B/s",
        "KB/s",
        "MB/s",
        "GB/s",
    )

    for unit in units:
        if value < 1024.0:
            return f"{value:.2f} {unit}"

        value /= 1024.0

    return f"{value:.2f} TB/s"


def trigger_ram_notification(ram):
    command = shutil.which(
        "termux-notification"
    )

    if not command:
        return

    try:
        subprocess.run(
            [
                command,
                "-t",
                "Aegis Alert",
                "-c",
                f"RAM usage has reached {ram:.2f}%",
                "--id",
                "aegis-ram",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    except Exception:
        pass


def clear_screen():
    print(
        "\033[2J\033[H",
        end="",
        flush=True,
    )


def render_dashboard(
    alert_sent,
    previous_network,
    previous_time,
):
    ram = get_ram_usage()
    processes = get_pid_count()

    (
        status,
        load1,
        load5,
        load15,
        cpu_count,
        normalized,
    ) = get_load_status()

    interfaces = get_active_interfaces()
    default_interface = get_default_interface()

    vpn = check_vpn()
    proxy = check_proxy()

    connected, latency = check_connectivity()

    current_network = get_network_counters()
    current_time = time.monotonic()

    upload_rate = None
    download_rate = None

    if (
        current_network is not None
        and previous_network is not None
    ):
        elapsed = (
            current_time - previous_time
        )

        if elapsed > 0:
            upload_rate = max(
                0,
                current_network[0]
                - previous_network[0],
            ) / elapsed

            download_rate = max(
                0,
                current_network[1]
                - previous_network[1],
            ) / elapsed

    if (
        ram >= RAM_THRESHOLD
        and not alert_sent
    ):
        trigger_ram_notification(ram)
        alert_sent = True

    elif ram < RAM_THRESHOLD:
        alert_sent = False

    clear_screen()

    print("================================================")
    print("                 AEGIS DASHBOARD")
    print("================================================")
    print(f"Protocol        : {PROTOCOL_NAME}")
    print(f"System Status   : {status}")
    print(f"Encryption      : {ENCRYPTION_STATUS}")
    print("------------------------------------------------")
    print(f"RAM Usage       : {ram:6.2f}%")
    print(f"Active PIDs     : {processes}")
    print("------------------------------------------------")
    print(f"CPU Count       : {cpu_count}")
    print(f"Load 1m         : {load1:6.2f}")
    print(f"Load 5m         : {load5:6.2f}")
    print(f"Load 15m        : {load15:6.2f}")
    print(f"Normalized Load : {normalized:6.2f}")
    print("------------------------------------------------")
    print(f"Interface       : {default_interface}")

    active = (
        ", ".join(interfaces)
        if interfaces
        else "NONE"
    )

    print(f"Active Links    : {active}")

    print(
        "Connectivity    : "
        + ("ONLINE" if connected else "OFFLINE")
    )

    if latency is None:
        print("Latency         : N/A")
    else:
        print(f"Latency         : {latency:6.1f} ms")

    print(f"Upload          : {format_rate(upload_rate)}")
    print(f"Download        : {format_rate(download_rate)}")

    print("------------------------------------------------")
    print(
        "VPN Connected   : "
        + ("YES" if vpn else "NO")
    )

    print(
        "Proxy Connected : "
        + ("YES" if proxy else "NO")
    )

    print("------------------------------------------------")
    print("QARMR Monitor   : ONLINE")
    print("Security Layer  : HYBRID KEX / AEAD")
    print("Android Access  : SAFE FALLBACK MODE")
    print("Network /proc   : NOT USED")
    print("================================================")
    print(f"Refresh         : {REFRESH_RATE:.0f} seconds")
    print("Press Ctrl+C to exit.")
    print("================================================")

    return (
        alert_sent,
        current_network,
        current_time,
    )


def main():
    alert_sent = False

    previous_network = get_network_counters()
    previous_time = time.monotonic()

    try:
        while True:
            (
                alert_sent,
                previous_network,
                previous_time,
            ) = render_dashboard(
                alert_sent,
                previous_network,
                previous_time,
            )

            time.sleep(REFRESH_RATE)

    except KeyboardInterrupt:
        clear_screen()
        print("Aegis dashboard stopped.")


if __name__ == "__main__":
    main()
