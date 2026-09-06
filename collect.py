from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup


# ============================================================
# CONFIG
# ============================================================

VPNGATE_URL = "https://www.vpngate.net/en/"

STATE_FILE = Path("data/servers.json")
OUTPUT_FILE = Path("data/sstp.txt")

UPDATE_INTERVAL = timedelta(hours=24)
SERVER_TTL = timedelta(hours=23, minutes=55)

REQUEST_TIMEOUT = 60

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/140.0 Safari/537.36"
    )
}


# ============================================================
# TIME
# ============================================================

def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def from_iso(value: str) -> datetime:
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
        with STATE_FILE.open("r", encoding="utf-8") as f:
            state = json.load(f)

        if not isinstance(state, dict):
            return default_state()

        if not isinstance(state.get("servers"), list):
            state["servers"] = []

        state.setdefault("last_update", None)

        return state

    except Exception as e:
        print(f"[!] Failed to load state: {e}")
        return default_state()


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    temp = STATE_FILE.with_suffix(".tmp")

    with temp.open("w", encoding="utf-8") as f:
        json.dump(
            state,
            f,
            ensure_ascii=False,
            indent=2
        )

    temp.replace(STATE_FILE)


# ============================================================
# HOSTNAME VALIDATION
# ============================================================

HOSTNAME_REGEX = re.compile(
    r"\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+"
    r"(?:\:\d{1,5})?\b"
)


def normalize_hostname(value: str) -> str | None:
    if not value:
        return None

    value = value.strip().lower()

    # حذف پورت
    value = value.split(":", 1)[0]

    # فقط opengw.net
    if not value.endswith(".opengw.net"):
        return None

    # جلوگیری از IP
    if re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}",
        value
    ):
        return None

    if len(value) > 253:
        return None

    return value


# ============================================================
# DOWNLOAD VPN GATE
# ============================================================

def download_vpngate() -> str:

    print("[+] Downloading VPN Gate...")

    response = requests.get(
        VPNGATE_URL,
        headers=HEADERS,
        timeout=REQUEST_TIMEOUT
    )

    response.raise_for_status()

    print(
        f"[+] HTTP Status: {response.status_code}"
    )

    return response.text


# ============================================================
# EXTRACT MS-SSTP HOSTNAMES
# ============================================================

def extract_sstp_hostnames(html: str) -> list[str]:

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    found: set[str] = set()

    rows = soup.find_all("tr")

    print(
        f"[+] Table rows found: {len(rows)}"
    )

    for row in rows:

        text = row.get_text(
            " ",
            strip=True
        )

        if not text:
            continue

        # فقط ردیف‌هایی که واقعاً MS-SSTP دارند
        if "SSTP Hostname" not in text:
            continue

        # ----------------------------------------------------
        # پیدا کردن hostname
        # ----------------------------------------------------

        matches = HOSTNAME_REGEX.findall(
            text
        )

        for match in matches:

            hostname = normalize_hostname(
                match
            )

            if hostname:
                found.add(
                    hostname
                )

                print(
                    f"[+] Found SSTP: {hostname}"
                )

    result = sorted(found)

    print()
    print(
        f"[+] Total unique MS-SSTP hostnames: "
        f"{len(result)}"
    )

    return result


# ============================================================
# EXPIRE OLD SERVERS
# ============================================================

def remove_expired(state: dict) -> int:

    current = now_utc()

    alive = []
    removed = 0

    for server in state["servers"]:

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
            created = from_iso(
                added_at
            )
        except Exception:
            removed += 1
            continue

        age = current - created

        if age >= SERVER_TTL:

            print(
                f"[-] Expired: {hostname}"
            )

            removed += 1

        else:

            alive.append(
                {
                    "hostname": hostname,
                    "added_at": added_at
                }
            )

    state["servers"] = alive

    return removed


# ============================================================
# CHECK 24H UPDATE
# ============================================================

def update_due(state: dict) -> bool:

    last_update = state.get(
        "last_update"
    )

    if not last_update:
        return True

    try:
        previous = from_iso(
            last_update
        )
    except Exception:
        return True

    return (
        now_utc() - previous
    ) >= UPDATE_INTERVAL


# ============================================================
# ADD SERVERS
# ============================================================

def add_servers(
    state: dict,
    hostnames: list[str]
) -> int:

    existing = {
        item.get("hostname")
        for item in state["servers"]
    }

    timestamp = to_iso(
        now_utc()
    )

    added = 0

    for hostname in hostnames:

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

    return added


# ============================================================
# WRITE TXT
# ============================================================

def write_output(state: dict) -> None:

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    hostnames = {
        item["hostname"]
        for item in state["servers"]
        if item.get("hostname")
    }

    hostnames = sorted(hostnames)

    temp = OUTPUT_FILE.with_suffix(".tmp")

    with temp.open(
        "w",
        encoding="utf-8",
        newline="\n"
    ) as f:

        for hostname in hostnames:
            f.write(
                hostname
                + "\n"
            )

    temp.replace(
        OUTPUT_FILE
    )

    print(
        f"[+] sstp.txt contains "
        f"{len(hostnames)} hostnames."
    )


# ============================================================
# MAIN
# ============================================================

def main() -> None:

    print()
    print("=" * 60)
    print("VPN GATE MS-SSTP COLLECTOR")
    print("=" * 60)
    print()

    state = load_state()

    # --------------------------------------------------------
    # Remove expired
    # --------------------------------------------------------

    removed = remove_expired(
        state
    )

    print(
        f"[+] Removed expired: {removed}"
    )

    # --------------------------------------------------------
    # 24-hour update
    # --------------------------------------------------------

    if update_due(state):

        print(
            "[+] 24-hour update is due."
        )

        try:

            html = download_vpngate()

            hostnames = extract_sstp_hostnames(
                html
            )

            if not hostnames:

                print(
                    "[!] No SSTP hostnames found."
                )

                print(
                    "[!] Existing data preserved."
                )

            else:

                added = add_servers(
                    state,
                    hostnames
                )

                print(
                    f"[+] New servers added: {added}"
                )

                # فقط وقتی دریافت موفق بوده
                state["last_update"] = to_iso(
                    now_utc()
                )

        except Exception as e:

            print(
                f"[!] Collection failed: {e}"
            )

            print(
                "[!] Existing servers preserved."
            )

    else:

        print(
            "[=] 24-hour update not due."
        )

    # --------------------------------------------------------
    # Final expiration cleanup
    # --------------------------------------------------------

    remove_expired(
        state
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    save_state(
        state
    )

    # --------------------------------------------------------
    # Output
    # --------------------------------------------------------

    write_output(
        state
    )

    print()
    print(
        f"[+] Active servers: "
        f"{len(state['servers'])}"
    )

    print("=" * 60)


if __name__ == "__main__":
    main()
