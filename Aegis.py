import psutil
import os
import time

# --- CONFIGURATION ---
PROTOCOL_NAME = "QARMR"
ENCRYPTION_STATUS = "Active - AEAD / Hybrid KEX"
RAM_THRESHOLD = 66.66
REFRESH_RATE = 2  # Seconds

def check_vpn():
    """Check for active VPN interfaces like tun0 or wg0."""
    interfaces = psutil.net_if_addrs().keys()
    return any(iface.startswith(('tun', 'tap', 'wg', 'ppp')) for iface in interfaces)

def check_proxy():
    """Check if proxy environment variables are set."""
    proxy_vars = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY']
    env_proxies = any(var in os.environ for var in proxy_vars)
    return env_proxies 

def get_system_status():
    """Determine system load status based on CPU."""
    try:
        cpu = psutil.cpu_percent(interval=0.1)
    except (PermissionError, OSError):
        # PLATFORM PATCH 2026-10-23: the ChromeOS/Android app sandbox
        # denies /proc/stat (probed live on the bench). Report the
        # blind spot plainly instead of crashing.
        return "Unavailable (OS restricted)"
    if cpu < 50: return "Optimal"
    elif cpu < 85: return "Under Load"
    else: return "Critical Load"

def get_net_snapshot():
    """Network byte counters, or None where the OS denies them.

    Android app sandboxes (including the ChromeOS container) block
    /proc/net/dev, which psutil reads on Linux -- probed live on the
    bench 2026-10-23: PermissionError there, while the RAM, PID and
    interface queries succeed. None lets the dashboard say so instead
    of crashing -- or worse, inventing numbers.
    """
    try:
        return psutil.net_io_counters()
    except (PermissionError, OSError):
        return None


def trigger_ram_notification(current_ram):
    """Fires a native Android notification via Termux API."""
    os.system(f"termux-notification -t 'System Alert' -c 'RAM usage is at {current_ram:.2f}% (Threshold: 2/3)' --id 1")

def format_speed(bytes_per_sec):
    """Converts bytes to a human-readable format."""
    for unit in ['B/s', 'KB/s', 'MB/s', 'GB/s']:
        if bytes_per_sec < 1024.0:
            return f"{bytes_per_sec:.2f} {unit}"
        bytes_per_sec /= 1024.0
    return f"{bytes_per_sec:.2f} TB/s"

def render_dashboard(upload_speed, download_speed):
    """Clears terminal and renders the updated UI."""
    ram_usage = psutil.virtual_memory().percent
    process_count = len(psutil.pids())
    vpn_status = "YES" if check_vpn() else "NO"
    proxy_status = "YES" if check_proxy() else "NO"
    sys_status = get_system_status()

    # Trigger notification if RAM hits or exceeds 2/3 (66.66%)
    if ram_usage >= RAM_THRESHOLD:
        trigger_ram_notification(ram_usage)

    os.system('clear')  # FIXED 2026-10-23: was os.Aegis('clear') -- no such attribute on os; would crash first render

    # PLATFORM PATCH 2026-10-23: speeds are None where the sandbox
    # blocks the counters -- say so, never print a fake zero.
    if upload_speed is None:
        up_text = "UNAVAILABLE (blocked by Android)"
        down_text = "UNAVAILABLE (blocked by Android)"
    else:
        up_text = format_speed(upload_speed)
        down_text = format_speed(download_speed)

    dashboard = f"""
    =========================================
               SYSTEM DASHBOARD
    =========================================
    Protocol        : {PROTOCOL_NAME}
    System Status   : {sys_status}
    Encryption      : {ENCRYPTION_STATUS}
    -----------------------------------------
    RAM Usage       : {ram_usage}% 
    Active PIDs     : {process_count} background processes
    -----------------------------------------
    Network Up      : {up_text}
    Network Down    : {down_text}
    -----------------------------------------
    VPN Connected   : {vpn_status}
    Proxy Connected : {proxy_status}
    =========================================
    Press Ctrl+C to exit.
    """
    print(dashboard)

def main_loop():
    """Main execution loop for tracking metrics and rendering UI."""
    # Take an initial snapshot before the loop starts
    # (None where the OS blocks the counters)
    net_io = get_net_snapshot()
    last_bytes_sent = net_io.bytes_sent if net_io is not None else None
    last_bytes_recv = net_io.bytes_recv if net_io is not None else None

    # Render an initial loading screen so it isn't blank for the first 2 seconds
    os.system('clear')
    print("Initializing System Dashboard...")

    try:
        while True:
            # Wait for the interval
            time.sleep(REFRESH_RATE)
            
            # Take a new snapshot
            net_io = get_net_snapshot()
            current_bytes_sent = net_io.bytes_sent if net_io is not None else None
            current_bytes_recv = net_io.bytes_recv if net_io is not None else None
            # --- RECONSTRUCTED TAIL (XiX draft, 2026-10-23, pending the Commander's review) ---
            # The repo copy of this file ended mid-loop at the snapshot above
            # (96 lines, try: never closed). Everything from this comment to
            # the end of the file is a reconstruction written to match the
            # surviving code -- it is NOT recovered original text.

            # Calculate transfer speeds over the refresh interval;
            # speeds stay None when the platform denies the counters,
            # and the dashboard prints UNAVAILABLE for them
            if current_bytes_sent is not None and last_bytes_sent is not None:
                upload_speed = (current_bytes_sent - last_bytes_sent) / REFRESH_RATE
                download_speed = (current_bytes_recv - last_bytes_recv) / REFRESH_RATE

                # Roll the snapshot forward
                last_bytes_sent = current_bytes_sent
                last_bytes_recv = current_bytes_recv
            else:
                upload_speed = None
                download_speed = None

            # Render the updated dashboard
            render_dashboard(upload_speed, download_speed)

    except KeyboardInterrupt:
        # Ctrl+C is the documented exit (see the dashboard footer)
        print("\nDashboard stopped. Exiting Aegis.")
        return


if __name__ == "__main__":
    main_loop()
