from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup


# ============================================================
# CONFIGURATION
# ============================================================

VPNGATE_URL = "https://www.vpngate.net/en/"

STATE_FILE = Path("data/servers.json")
OUTPUT_FILE = Path("data/sstp.txt")

# دریافت Batch جدید هر 24 ساعت
UPDATE_INTERVAL = timedelta(hours=24)

# هر سرور بعد از 23 ساعت و 55 دقیقه منقضی می‌شود
SERVER_TTL = timedelta(hours=23, minutes=55)

REQUEST_TIMEOUT = 45

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/140.0 Safari/537.36"
    )
}


# ============================================================
# TIME
# ============================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def datetime_to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def iso_to_datetime(value: str) -> datetime:
    return datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )


# ============================================================
# STATE
# ============================================================

def default_state() -> dict:
    return {
        "last_update": None,
        "servers": []
    }


def load_state() -> dict:
    if not STATE_FILE.exists():
        return default_state()

    try:
        with STATE_FILE.open("r", encoding="utf-8") as file:
            state = json.load(file)

        if not isinstance(state, dict):
            return default_state()

        state.setdefault("last_update", None)
        state.setdefault("servers", [])

        if not isinstance(state["servers"], list):
            state["servers"] = []

        return state

    except Exception as exc:
        print(f"[!] Failed to read state: {exc}")
        return default_state()


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temp_file = STATE_FILE.with_suffix(".tmp")

    with temp_file.open("w", encoding="utf-8") as file:
        json.dump(
            state,
            file,
            ensure_ascii=False,
            indent=2
        )

    temp_file.replace(STATE_FILE)


# ============================================================
# HOSTNAME VALIDATION
# ============================================================

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def is_valid_hostname(hostname: str) -> bool:
    if not hostname:
        return False

    hostname = hostname.strip().lower()

    # ما IP عددی نمی‌خواهیم
    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        hostname
    ):
        return False

    # فقط Hostname های opengw.net
    if not hostname.endswith(".opengw.net"):
        return False

    return bool(HOSTNAME_PATTERN.fullmatch(hostname))


# ============================================================
# EXTRACT SSTP HOSTNAME FROM CELL
# ============================================================

def extract_hostname_from_text(text: str) -> str | None:
    """
    مثال:

    SSTP Hostname :
    vpn294043338.opengw.net:1649

    خروجی:

    vpn294043338.opengw.net
    """

    if not text:
        return None

    text = " ".join(text.split())

    # پیدا کردن hostname به همراه پورت اختیاری
    match = re.search(
        r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+"
        r"(?:\:\d{1,5})?\b",
        text
    )

    if not match:
        return None

    hostname = match.group(0).strip().lower()

    # حذف پورت
    hostname = hostname.split(":", 1)[0]

    if not is_valid_hostname(hostname):
        return None

    return hostname


# ============================================================
# DOWNLOAD VPN GATE
# ============================================================

def download_vpngate_page() -> str:
    print("[+] Downloading VPN Gate server list...")

    response = requests.get(
        VPNGATE_URL,
        headers=HEADERS,
        timeout=REQUEST_TIMEOUT
    )

    response.raise_for_status()

    # VPN Gate فعلاً HTML است
    response.encoding = response.apparent_encoding

    return response.text


# ============================================================
# FIND MS-SSTP COLUMN
# ============================================================

def find_sstp_column_indexes(table) -> list[int]:
    """
    سعی می‌کند ستون MS-SSTP را از header جدول پیدا کند.
    """

    rows = table.find_all("tr")

    for row in rows:

        headers = row.find_all(
            ["th", "td"]
        )

        if not headers:
            continue

        for index, cell in enumerate(headers):

            text = cell.get_text(
                " ",
                strip=True
            ).lower()

            normalized = re.sub(
                r"\s+",
                " ",
                text
            )

            if (
                "ms-sstp" in normalized
                or "ms sstp" in normalized
            ):
                return [index]

    return []


# ============================================================
# EXTRACT MS-SSTP HOSTNAMES
# ============================================================

def extract_sstp_hostnames(html: str) -> list[str]:

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    hostnames: set[str] = set()

    tables = soup.find_all("table")

    print(
        f"[+] HTML tables detected: {len(tables)}"
    )

    for table in tables:

        rows = table.find_all("tr")

        if not rows:
            continue

        # ----------------------------------------------------
        # Try to detect exact MS-SSTP column
        # ----------------------------------------------------

        sstp_indexes = find_sstp_column_indexes(
            table
        )

        if sstp_indexes:

            for row in rows:

                cells = row.find_all(
                    ["td", "th"]
                )

                for index in sstp_indexes:

                    if index >= len(cells):
                        continue

                    cell = cells[index]

                    text = cell.get_text(
                        " ",
                        strip=True
                    )

                    hostname = extract_hostname_from_text(
                        text
                    )

                    if hostname:
                        hostnames.add(
                            hostname
                        )

        else:

            # ------------------------------------------------
            # Fallback:
            # Search only cells containing SSTP Hostname
            # ------------------------------------------------

            for row in rows:

                cells = row.find_all(
                    ["td", "th"]
                )

                for cell in cells:

                    text = cell.get_text(
                        " ",
                        strip=True
                    )

                    if not text:
                        continue

                    lower_text = text.lower()

                    if "sstp hostname" not in lower_text:
                        continue

                    hostname = extract_hostname_from_text(
                        text
                    )

                    if hostname:
                        hostnames.add(
                            hostname
                        )

    result = sorted(hostnames)

    print(
        f"[+] MS-SSTP hostnames found: {len(result)}"
    )

    return result


# ============================================================
# EXPIRATION
# ============================================================

def remove_expired_servers(state: dict) -> int:

    current = now_utc()

    valid_servers = []
    removed = 0

    for server in state.get(
        "servers",
        []
    ):

        hostname = server.get(
            "hostname"
        )

        added_at = server.get(
            "added_at"
        )

        if not hostname or not added_at:
            removed += 1
            continue

        try:
            added_time = iso_to_datetime(
                added_at
            )

        except Exception:
            removed += 1
            continue

        age = current - added_time

        if age >= SERVER_TTL:

            print(
                f"[-] Expired: {hostname}"
            )

            removed += 1

        else:

            valid_servers.append(
                server
            )

    state["servers"] = valid_servers

    return removed


# ============================================================
# UPDATE CHECK
# ============================================================

def should_update(state: dict) -> bool:

    last_update = state.get(
        "last_update"
    )

    if not last_update:
        return True

    try:
        last_update_time = iso_to_datetime(
            last_update
        )

    except Exception:
        return True

    elapsed = (
        now_utc()
        - last_update_time
    )

    return elapsed >= UPDATE_INTERVAL


# ============================================================
# ADD NEW SERVERS
# ============================================================

def add_new_servers(
    state: dict,
    hostnames: list[str]
) -> int:

    existing = {
        server.get("hostname")
        for server in state.get(
            "servers",
            []
        )
    }

    timestamp = datetime_to_iso(
        now_utc()
    )

    added = 0

    for hostname in hostnames:

        hostname = hostname.strip().lower()

        if not is_valid_hostname(
            hostname
        ):
            continue

        if hostname in existing:
            continue

        state["servers"].append(
            {
                "hostname": hostname,
                "added_at": timestamp
            }
        )

        existing.add(
            hostname
        )

        added += 1

        print(
            f"[+] Added: {hostname}"
        )

    return added


# ============================================================
# WRITE OUTPUT TXT
# ============================================================

def write_output(state: dict) -> None:

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    hostnames = set()

    for server in state.get(
        "servers",
        []
    ):

        hostname = server.get(
            "hostname"
        )

        if not hostname:
            continue

        hostname = hostname.strip().lower()

        if is_valid_hostname(
            hostname
        ):
            hostnames.add(
                hostname
            )

    sorted_hostnames = sorted(
        hostnames
    )

    temp_file = OUTPUT_FILE.with_suffix(
        ".tmp"
    )

    with temp_file.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as file:

        for hostname in sorted_hostnames:
            file.write(
                hostname
                + "\n"
            )

    temp_file.replace(
        OUTPUT_FILE
    )

    print(
        f"[+] Output written: "
        f"{len(sorted_hostnames)} hosts"
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print()
    print("=" * 60)
    print(" VPN GATE MS-SSTP COLLECTOR")
    print("=" * 60)

    state = load_state()

    # --------------------------------------------------------
    # 1. Remove expired servers
    # --------------------------------------------------------

    removed = remove_expired_servers(
        state
    )

    print(
        f"[+] Expired removed: {removed}"
    )

    # --------------------------------------------------------
    # 2. Check 24 hour update
    # --------------------------------------------------------

    if should_update(state):

        print(
            "[+] 24-hour update is due."
        )

        try:

            html = download_vpngate_page()

            hostnames = extract_sstp_hostnames(
                html
            )

            if not hostnames:

                print(
                    "[!] No MS-SSTP hostname found."
                )

                print(
                    "[!] Existing servers preserved."
                )

            else:

                added = add_new_servers(
                    state,
                    hostnames
                )

                print(
                    f"[+] New servers added: {added}"
                )

                # فقط وقتی دریافت موفق بود
                # زمان آخرین Update را ثبت می‌کنیم
                state["last_update"] = (
                    datetime_to_iso(
                        now_utc()
                    )
                )

        except requests.RequestException as exc:

            print(
                f"[!] VPN Gate request failed: {exc}"
            )

            print(
                "[!] Keeping old servers."
            )

        except Exception as exc:

            print(
                f"[!] Unexpected error: {exc}"
            )

            print(
                "[!] Keeping old servers."
            )

    else:

        print(
            "[=] 24-hour update is not due yet."
        )

    # --------------------------------------------------------
    # 3. Final expiration cleanup
    # --------------------------------------------------------

    remove_expired_servers(
        state
    )

    # --------------------------------------------------------
    # 4. Save JSON state
    # --------------------------------------------------------

    save_state(
        state
    )

    # --------------------------------------------------------
    # 5. Generate TXT
    # --------------------------------------------------------

    write_output(
        state
    )

    print("=" * 60)
    print(
        f"[+] Active servers: "
        f"{len(state.get('servers', []))}"
    )
    print("=" * 60)


if __name__ == "__main__":
    main()