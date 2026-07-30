#!/usr/bin/env python3
import argparse
import csv
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import urllib.parse
import string
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, unquote


# === HEIMDALL UI HELPERS ===
UI_RESET = "\033[0m"
UI_PURPLE = "\033[38;5;141m"
UI_CYAN = "\033[38;5;117m"

def ui_rule():
    width = globals().get("UI_BOX_WIDTH", 44)
    print(f"{UI_PURPLE}{'─' * width}{UI_RESET}")

def ui_box_header(title, subtitle=None):
    width = globals().get("UI_BOX_WIDTH", 44)
    title = str(title)

    if len(title) > width:
        width = len(title) + 2

    left = (width - len(title)) // 2
    right = width - len(title) - left
    line = "─" * width

    print()
    print(f"{UI_PURPLE}╭{line}╮{UI_RESET}")
    print(f"{UI_PURPLE}│{' ' * left}{title}{' ' * right}│{UI_RESET}")
    print(f"{UI_PURPLE}╰{line}╯{UI_RESET}")

def ui_title(title):
    print()
    print(f"{UI_PURPLE}{title}{UI_RESET}")
    ui_rule()

def ui_item(num, label):
    color = "203" if str(num) == "0" else "117"
    print(f"  [38;5;{color}m{num})[0m {label}")

def ui_input(prompt_text):
    return input(f"\033[1;38;5;141m{prompt_text}\033[0m")
# === END HEIMDALL UI HELPERS ===


HEIMDALL_DB = os.environ.get("HEIMDALL_DB", "xui")
PSQL_USER = os.environ.get("PSQL_USER", "postgres")
ALPHABET = string.ascii_lowercase + string.digits

REQUIRED_SOURCE_COLUMNS = [
    "id",
    "username",
    "status",
    "used_traffic",
    "data_limit",
    "created_at",
    "note",
    "edit_at",
    "last_status_change",
    "expire",
    "proxy_settings",
    "on_hold_timeout",
    "on_hold_expire_duration",
    "data_limit_reset_strategy",
    "hwid_limit",
]

def die(msg):
    print(f"STOP: {msg}", file=sys.stderr)
    sys.exit(1)

def now_ms():
    return int(datetime.now(timezone.utc).timestamp() * 1000)

def token(n=16):
    return "".join(secrets.choice(ALPHABET) for _ in range(n))

def sql_literal(value):
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    s = str(value).replace("'", "''")
    return f"'{s}'"

def run_cmd(cmd, input_text=None, env=None):
    res = subprocess.run(cmd, input=input_text, text=True, capture_output=True, env=env, cwd="/tmp")
    if res.returncode != 0:
        if res.stdout:
            print(res.stdout)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        die(f"command failed: {' '.join(cmd)}")
    return res.stdout, res.stderr

def run_heimdall_psql(sql):
    cmd = ["sudo", "-u", PSQL_USER, "psql", "-d", HEIMDALL_DB, "-v", "ON_ERROR_STOP=1", "-Atc", sql]
    out, _ = run_cmd(cmd)
    return out

def run_heimdall_psql_script(sql):
    cmd = ["sudo", "-u", PSQL_USER, "psql", "-d", HEIMDALL_DB, "-v", "ON_ERROR_STOP=1"]
    return run_cmd(cmd, input_text=sql)

def parse_env_file(path):
    result = {}
    p = Path(path)
    if not p.exists():
        return result

    for raw in p.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip("'").strip('"')
        result[k] = v
    return result

def detect_pasarguard_db_url():
    manual = (
        os.environ.get("PASARGUARD_DATABASE_URL")
        or os.environ.get("SQLALCHEMY_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
    )
    if manual:
        return manual, "environment"

    env_paths = [
        "/opt/pasarguard/.env",
        "/app/.env",
        "/root/pasarguard/.env",
    ]

    for path in env_paths:
        env = parse_env_file(path)
        for key in ["SQLALCHEMY_DATABASE_URL", "DATABASE_URL"]:
            if env.get(key):
                return env[key], path

    sqlite_fallbacks = [
        "/var/lib/pasarguard/db.sqlite3",
        "/opt/pasarguard/db.sqlite3",
        "/opt/pasarguard/database.sqlite3",
    ]

    for path in sqlite_fallbacks:
        if Path(path).exists():
            return "sqlite+aiosqlite:////" + str(Path(path)).lstrip("/"), "fallback-sqlite"

    die("could not detect PasarGuard database URL")

def sqlite_url_to_path(url):
    tail = url.split(":", 1)[1]
    if tail.startswith("////"):
        return Path("/" + tail.lstrip("/"))
    if tail.startswith("///"):
        return Path(tail[3:]).resolve()
    if tail.startswith("//"):
        return Path(tail[2:]).resolve()
    return Path(tail).resolve()

def normalize_postgres_url(url):
    url = re.sub(r"^postgresql\+[^:]+://", "postgresql://", url)
    url = re.sub(r"^postgres\+[^:]+://", "postgres://", url)
    url = re.sub(r"^timescale(?:db)?\+[^:]+://", "postgresql://", url)
    url = re.sub(r"^timescale(?:db)?://", "postgresql://", url)
    return url


def mask_db_url(url):
    value = str(url or "")
    if not value:
        return value

    try:
        parsed = urllib.parse.urlsplit(value)
        if not parsed.username and not parsed.password:
            return value

        username = urllib.parse.quote(urllib.parse.unquote(parsed.username or ""), safe="")
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""

        auth = username
        if parsed.password is not None:
            auth += ":***"

        netloc = f"{auth}@{host}{port}"
        return urllib.parse.urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    except Exception:
        return re.sub(r":([^:@/]+)@", ":***@", value)

def parse_json(value):
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    return {}

def parse_dt_to_ms(value):
    if not value:
        return 0, "none"
    s = str(value).strip()
    candidates = [
        s,
        s.replace(" ", "T"),
        s.replace("Z", "+00:00"),
        s.replace(" ", "T").replace("Z", "+00:00"),
    ]
    for c in candidates:
        try:
            dt = datetime.fromisoformat(c)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000), "parsed"
        except Exception:
            pass
    return 0, f"unparsed:{s}"

def valid_uuid_or_none(value):
    try:
        return str(uuid.UUID(str(value)))
    except Exception:
        return None

def get_nested(d, *keys):
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(k)
    return cur

def bytes_human(n):
    return f"{int(n or 0) / 1024 / 1024 / 1024:.4f} GiB"

def load_sqlite_users(db_url, user_like):
    db_path = sqlite_url_to_path(db_url)
    if not db_path.exists():
        die(f"SQLite DB not found: {db_path}")

    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    rows = cur.execute(f"""
SELECT {", ".join(REQUIRED_SOURCE_COLUMNS)}
FROM users
WHERE username LIKE ?
ORDER BY id ASC
""", (user_like,)).fetchall()

    con.close()
    return [dict(r) for r in rows], f"sqlite:{db_path}"

def load_postgres_users(db_url, user_like):
    if not shutil.which("psql"):
        die("psql client not found; install postgresql-client to read PostgreSQL/TimescaleDB PasarGuard source")

    dsn = normalize_postgres_url(db_url)

    sql = f"""
SELECT COALESCE(json_agg(row_to_json(t))::text, '[]')
FROM (
  SELECT
    id,
    username,
    status,
    used_traffic,
    data_limit,
    created_at::text AS created_at,
    note,
    edit_at::text AS edit_at,
    last_status_change::text AS last_status_change,
    expire::text AS expire,
    proxy_settings::text AS proxy_settings,
    on_hold_timeout::text AS on_hold_timeout,
    on_hold_expire_duration,
    data_limit_reset_strategy,
    hwid_limit
  FROM users
  WHERE username LIKE {sql_literal(user_like)}
  ORDER BY id ASC
) t;
"""

    out, _ = run_cmd(["psql", "-d", dsn, "-v", "ON_ERROR_STOP=1", "-Atc", sql])
    text = out.strip() or "[]"
    return json.loads(text), "postgres/timescale"

def load_mysql_users(db_url, user_like):
    if not shutil.which("mysql"):
        die("mysql client not found; install mysql-client/mariadb-client to read MySQL/MariaDB PasarGuard source")

    parsed = urlparse(db_url)
    host = parsed.hostname or "127.0.0.1"
    port = str(parsed.port or 3306)
    user = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    dbname = parsed.path.lstrip("/")

    if not user or not dbname:
        die("invalid MySQL/MariaDB database URL; username and database name are required")

    sql = f"""
SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
  'id', id,
  'username', username,
  'status', status,
  'used_traffic', used_traffic,
  'data_limit', data_limit,
  'created_at', CAST(created_at AS CHAR),
  'note', note,
  'edit_at', CAST(edit_at AS CHAR),
  'last_status_change', CAST(last_status_change AS CHAR),
  'expire', CAST(expire AS CHAR),
  'proxy_settings', CAST(proxy_settings AS CHAR),
  'on_hold_timeout', CAST(on_hold_timeout AS CHAR),
  'on_hold_expire_duration', on_hold_expire_duration,
  'data_limit_reset_strategy', data_limit_reset_strategy,
  'hwid_limit', hwid_limit
)), JSON_ARRAY())
FROM users
WHERE username LIKE {sql_literal(user_like)}
ORDER BY id ASC;
"""

    env = os.environ.copy()
    if password:
        env["MYSQL_PWD"] = password

    cmd = [
        "mysql",
        "--protocol=tcp",
        "-h", host,
        "-P", port,
        "-u", user,
        "--batch",
        "--raw",
        "--skip-column-names",
        dbname,
        "-e", sql,
    ]

    out, _ = run_cmd(cmd, env=env)
    text = out.strip() or "[]"
    return json.loads(text), "mysql/mariadb"

def load_pasarguard_users(db_url, user_like):
    scheme = db_url.split(":", 1)[0].lower()

    if scheme.startswith("sqlite"):
        return load_sqlite_users(db_url, user_like)

    if scheme.startswith("postgres") or scheme.startswith("timescale"):
        return load_postgres_users(db_url, user_like)

    if scheme.startswith("mysql") or scheme.startswith("mariadb"):
        return load_mysql_users(db_url, user_like)

    die(f"unsupported PasarGuard DB scheme: {scheme}")


def detect_marzban_db_url():
    env_url = (
        os.environ.get("MARZBAN_DATABASE_URL")
        or os.environ.get("MARZBAN_SQLALCHEMY_DATABASE_URL")
        or os.environ.get("SQLALCHEMY_DATABASE_URL")
    )
    if env_url:
        return env_url.strip().strip('"').strip("'"), "env"

    env_paths = [
        "/opt/marzban/.env",
        "/root/marzban/.env",
    ]

    for path in env_paths:
        data = parse_env_file(path)
        for key in ("SQLALCHEMY_DATABASE_URL", "DATABASE_URL"):
            if data.get(key):
                return data[key], path

    sqlite_fallbacks = [
        "/var/lib/marzban/db.sqlite3",
        "/opt/marzban/db.sqlite3",
        "/opt/marzban/database.sqlite3",
    ]

    for path in sqlite_fallbacks:
        if Path(path).exists():
            return "sqlite:////" + str(Path(path)).lstrip("/"), "fallback-sqlite"

    die("could not detect Marzban database URL")


def _normalize_marzban_proxy_type(value):
    v = str(value or "").strip()
    low = v.lower().replace("-", "").replace("_", "").replace(" ", "")
    if low in {"shadowsocks", "ss"}:
        return "shadowsocks"
    if low in {"vless"}:
        return "vless"
    if low in {"vmess"}:
        return "vmess"
    if low in {"trojan"}:
        return "trojan"
    return str(value or "").strip().lower()


def load_marzban_sqlite_users(db_url, user_like):
    db_path = sqlite_url_to_path(db_url)
    if not Path(db_path).exists():
        die(f"Marzban SQLite DB not found: {db_path}")

    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    sql = """
    SELECT
      u.id AS user_id,
      u.username,
      u.status,
      u.used_traffic,
      u.data_limit,
      u.expire,
      u.note,
      p.id AS proxy_id,
      p.type AS proxy_type,
      p.settings AS proxy_settings
    FROM users u
    LEFT JOIN proxies p ON p.user_id = u.id
    WHERE u.username LIKE ?
    ORDER BY u.id, p.id
    """

    grouped = {}

    for r in cur.execute(sql, (user_like,)):
        d = dict(r)
        uid = d.get("user_id")

        if uid not in grouped:
            grouped[uid] = {
                "_source_label": "Marzban",
                "_source_panel": "marzban",
                "id": uid,
                "username": d.get("username"),
                "status": d.get("status"),
                "used_traffic": d.get("used_traffic") or 0,
                "data_limit": d.get("data_limit"),
                "expire": d.get("expire"),
                "note": d.get("note") or "",
                "proxies": {},
                "source_proxies": [],
            }

        proxy_type = d.get("proxy_type")
        raw_settings = d.get("proxy_settings")

        if proxy_type:
            settings = parse_json(raw_settings) or {}
            normalized = _normalize_marzban_proxy_type(proxy_type)

            grouped[uid]["source_proxies"].append({
                "id": d.get("proxy_id"),
                "type": proxy_type,
                "settings": settings,
            })

            # PasarGuard-compatible proxy map for the existing importer core.
            grouped[uid]["proxies"][normalized] = settings
            grouped[uid]["proxies"][str(proxy_type).strip()] = settings

            if normalized == "shadowsocks":
                grouped[uid]["proxies"]["ss"] = settings
                grouped[uid]["proxies"]["Shadowsocks"] = settings

    con.close()

    rows = []
    for row in grouped.values():
        row["proxies"] = json.dumps(row.get("proxies") or {}, ensure_ascii=False)
        row["source_proxies"] = json.dumps(row.get("source_proxies") or [], ensure_ascii=False)
        rows.append(row)

    return rows, "sqlite"


def load_marzban_mysql_users(db_url, user_like):
    if not shutil.which("mysql"):
        die("mysql client not found; install mysql-client/mariadb-client to read MySQL/MariaDB Marzban source")

    parsed = urllib.parse.urlparse(db_url)
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    host = parsed.hostname or "127.0.0.1"
    port = str(parsed.port or 3306)
    dbname = (parsed.path or "").lstrip("/")

    if not username or not dbname:
        die("invalid MySQL/MariaDB Marzban database URL; username and database name are required")

    query = f"""
SELECT
  u.id AS user_id,
  u.username,
  u.status,
  IFNULL(u.used_traffic, 0) AS used_traffic,
  u.data_limit,
  u.expire,
  IFNULL(u.note, '') AS note,
  p.id AS proxy_id,
  p.type AS proxy_type,
  p.settings AS proxy_settings
FROM users u
LEFT JOIN proxies p ON p.user_id = u.id
WHERE u.username LIKE {sql_literal(user_like)}
ORDER BY u.id, p.id;
"""

    env = os.environ.copy()
    if password:
        env["MYSQL_PWD"] = password

    cmd = [
        "mysql",
        "-N",
        "-B",
        "--raw",
        "-h", host,
        "-P", port,
        "-u", username,
        dbname,
    ]

    result = run_cmd(cmd, input_text=query + "\n", env=env)
    if isinstance(result, tuple):
        text = result[0]
    else:
        text = result
    text = (text or "").strip()

    def clean(v):
        if v in {None, "NULL", "\\N"}:
            return None
        return v

    def to_int_or_none(v):
        v = clean(v)
        if v is None or v == "":
            return None
        return int(v)

    grouped = {}

    for line in text.splitlines():
        if not line.strip():
            continue

        parts = line.split("\t")
        if len(parts) < 10:
            die(f"unexpected Marzban MySQL row shape: {line!r}")

        user_id, username, status, used_traffic, data_limit, expire, note, proxy_id, proxy_type, proxy_settings = parts[:10]

        uid = int(user_id)

        if uid not in grouped:
            grouped[uid] = {
                "_source_label": "Marzban",
                "_source_panel": "marzban",
                "id": uid,
                "username": clean(username),
                "status": clean(status),
                "used_traffic": to_int_or_none(used_traffic) or 0,
                "data_limit": to_int_or_none(data_limit),
                "expire": to_int_or_none(expire),
                "note": clean(note) or "",
                "proxies": {},
                "source_proxies": [],
            }

        proxy_type = clean(proxy_type)
        proxy_settings = clean(proxy_settings)

        if proxy_type:
            settings = parse_json(proxy_settings) or {}
            normalized = _normalize_marzban_proxy_type(proxy_type)

            grouped[uid]["source_proxies"].append({
                "id": to_int_or_none(proxy_id),
                "type": proxy_type,
                "settings": settings,
            })

            grouped[uid]["proxies"][normalized] = settings
            grouped[uid]["proxies"][proxy_type] = settings

            if normalized == "shadowsocks":
                grouped[uid]["proxies"]["ss"] = settings
                grouped[uid]["proxies"]["Shadowsocks"] = settings

    rows = []
    for row in grouped.values():
        row["proxies"] = json.dumps(row.get("proxies") or {}, ensure_ascii=False)
        row["source_proxies"] = json.dumps(row.get("source_proxies") or [], ensure_ascii=False)
        rows.append(row)

    return rows, "mysql/mariadb"

def load_marzban_users(db_url, user_like):
    scheme = urllib.parse.urlparse(db_url).scheme

    if scheme.startswith("sqlite"):
        return load_marzban_sqlite_users(db_url, user_like)

    if scheme.startswith("mysql") or scheme.startswith("mariadb"):
        return load_marzban_mysql_users(db_url, user_like)

    die(f"unsupported Marzban DB scheme in this build: {scheme}")


def detect_hiddify_db_url():
    manual = (
        os.environ.get("HIDDIFY_DATABASE_URL")
        or os.environ.get("HIDDIFY_SQLALCHEMY_DATABASE_URI")
        or os.environ.get("SQLALCHEMY_DATABASE_URI")
    )
    if manual:
        return manual.strip().strip('"').strip("'"), "env"

    # Native Hiddify installs use local MariaDB. Root socket access is enough
    # for read-only discovery and avoids exposing/storing panel DB passwords.
    if shutil.which("mysql"):
        try:
            out, _ = run_cmd([
                "mysql",
                "--protocol=socket",
                "-uroot",
                "-N",
                "-B",
                "-e",
                "SHOW DATABASES LIKE 'hiddifypanel';",
            ])
            if "hiddifypanel" in (out or ""):
                return "mysql+mysqldb://root@localhost/hiddifypanel?unix_socket=1", "local-mariadb-root-socket"
        except Exception:
            pass

    env_paths = [
        "/opt/hiddify-manager/hiddify-panel/app.cfg",
        "/opt/hiddify-manager/docker.env",
        "/opt/hiddify-manager/.env",
    ]

    for path in env_paths:
        data = parse_env_file(path)
        for key in ("SQLALCHEMY_DATABASE_URI", "DATABASE_URL"):
            if data.get(key):
                return data[key], path

        if data.get("MYSQL_PASSWORD"):
            return (
                "mysql+mysqldb://hiddifypanel:"
                + urllib.parse.quote(data["MYSQL_PASSWORD"])
                + "@localhost/hiddifypanel?charset=utf8mb4"
            ), path

    die("could not detect Hiddify database URL")


def load_hiddify_mysql_users(db_url, user_like):
    if not shutil.which("mysql"):
        die("mysql client not found; install mysql-client/mariadb-client to read Hiddify MariaDB source")

    parsed = urllib.parse.urlparse(db_url)
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    host = parsed.hostname or "127.0.0.1"
    port = str(parsed.port or 3306)
    dbname = (parsed.path or "").lstrip("/") or "hiddifypanel"

    if not dbname:
        die("invalid Hiddify database URL; database name is required")

    query = f"""
SELECT COALESCE(JSON_ARRAYAGG(JSON_OBJECT(
  'id', u.id,
  'uuid', u.uuid,
  'name', u.name,
  'source_username', u.username,
  'status', IF(u.enable = 1, 'active', 'disabled'),
  'used_traffic', IFNULL(u.current_usage, 0),
  'data_limit', IFNULL(u.usage_limit, 0),
  'expire',
    CASE
      WHEN IFNULL(u.package_days, 0) > 0
      THEN CAST(DATE_ADD(COALESCE(u.start_date, u.last_reset_time, CURRENT_DATE()), INTERVAL u.package_days DAY) AS CHAR)
      ELSE NULL
    END,
  'note', IFNULL(u.comment, ''),
  'package_days', IFNULL(u.package_days, 0),
  'data_limit_reset_strategy', u.mode,
  'mode', u.mode,
  'max_ips', IFNULL(u.max_ips, 0),
  'hwid_limit', IFNULL(u.max_ips, 0),
  'start_date', CAST(u.start_date AS CHAR),
  'last_reset_time', CAST(u.last_reset_time AS CHAR),
  'proxy_settings', JSON_OBJECT(
      'vless', JSON_OBJECT('id', u.uuid),
      'vmess', JSON_OBJECT('id', u.uuid),
      'trojan', JSON_OBJECT('password', u.uuid)
  )
)), JSON_ARRAY())
FROM (
  SELECT *
  FROM `user`
  WHERE name LIKE {sql_literal(user_like)}
     OR username LIKE {sql_literal(user_like)}
  ORDER BY id ASC
) u;
"""

    env = os.environ.copy()

    if parsed.query and "unix_socket=1" in parsed.query:
        cmd = [
            "mysql",
            "--protocol=socket",
            "-uroot",
            "--default-character-set=utf8mb4",
            "-N",
            "-B",
            "--raw",
            dbname,
        ]
    else:
        if not username:
            die("invalid Hiddify database URL; username is required unless unix_socket=1 is used")

        if password:
            env["MYSQL_PWD"] = password

        cmd = [
            "mysql",
            "-N",
            "-B",
            "--raw",
            "--default-character-set=utf8mb4",
            "-h", host,
            "-P", port,
            "-u", username,
            dbname,
        ]

    result = run_cmd(cmd, input_text=query + "\n", env=env)
    if isinstance(result, tuple):
        text = result[0]
    else:
        text = result

    text = (text or "").strip() or "[]"
    rows = json.loads(text)

    normalized_rows = []
    for row in rows:
        source_name = str(row.get("name") or "").strip()
        source_username = str(row.get("source_username") or "").strip()

        # Important: Hiddify's username has a random suffix. The real human
        # client name is user.name, so map user.name -> PRIMEVPN email/name.
        target_name = source_name or source_username or str(row.get("uuid") or "").strip()
        if not target_name:
            continue

        source_uuid = valid_uuid_or_none(row.get("uuid"))
        proxy_settings = row.get("proxy_settings") or {}
        if source_uuid:
            proxy_settings = {
                "vless": {"id": source_uuid},
                "vmess": {"id": source_uuid},
                "trojan": {"password": source_uuid},
            }

        row["_source_label"] = "Hiddify"
        row["_source_panel"] = "hiddify"
        row["username"] = target_name
        row["status"] = row.get("status") or "active"
        row["used_traffic"] = int(row.get("used_traffic") or 0)
        row["data_limit"] = int(row.get("data_limit") or 0)
        row["note"] = row.get("note") or ""
        row["proxy_settings"] = json.dumps(proxy_settings, ensure_ascii=False)
        normalized_rows.append(row)

    return normalized_rows, "mariadb"


def load_hiddify_users(db_url, user_like):
    scheme = urllib.parse.urlparse(db_url).scheme

    if scheme.startswith("mysql") or scheme.startswith("mariadb"):
        return load_hiddify_mysql_users(db_url, user_like)

    die(f"unsupported Hiddify DB scheme in this build: {scheme}")

def panel_display_name(panel):
    panel = str(panel or "").strip().lower()
    if panel == "pasarguard":
        return "PasarGuard"
    if panel == "marzban":
        return "Marzban"
    if panel == "hiddify":
        return "Hiddify"
    return panel or "Unknown"


def detect_source_db_url(panel):
    panel = str(panel or "").strip().lower()
    if panel == "pasarguard":
        return detect_pasarguard_db_url()
    if panel == "marzban":
        return detect_marzban_db_url()
    if panel == "hiddify":
        return detect_hiddify_db_url()
    die(f"unsupported source panel: {panel}")


def load_source_users(panel, db_url, user_like):
    panel = str(panel or "").strip().lower()
    if panel == "pasarguard":
        return load_pasarguard_users(db_url, user_like)
    if panel == "marzban":
        return load_marzban_users(db_url, user_like)
    if panel == "hiddify":
        return load_hiddify_users(db_url, user_like)
    die(f"unsupported source panel: {panel}")

def parse_inbound_ids(raw):
    raw = (raw or "").strip()
    if not raw:
        return []

    ids = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit():
            die(f"invalid inbound id: {part}")
        ids.append(int(part))

    clean = []
    seen = set()
    for i in ids:
        if i not in seen:
            clean.append(i)
            seen.add(i)
    return clean

def validate_heimdall_tables():
    required = {"clients", "client_inbounds", "client_traffics", "inbounds"}
    out = run_heimdall_psql("""
SELECT table_name
FROM information_schema.tables
WHERE table_schema='public'
  AND table_name IN ('clients','client_inbounds','client_traffics','inbounds')
ORDER BY table_name;
""")
    found = set(x.strip() for x in out.splitlines() if x.strip())
    missing = sorted(required - found)
    if missing:
        die(f"missing PRIMEVPN tables: {missing}")

def fetch_heimdall_inbounds():
    out = run_heimdall_psql("""
SELECT
  id || '|' ||
  COALESCE(protocol,'') || '|' ||
  COALESCE(port::text,'') || '|' ||
  COALESCE(tag,'') || '|' ||
  COALESCE(remark,'') || '|' ||
  COALESCE(enable::text,'')
FROM inbounds
ORDER BY id;
""")
    rows = []
    for line in out.splitlines():
        if not line.strip():
            continue
        p = line.split("|")
        rows.append({
            "id": int(p[0]),
            "protocol": p[1],
            "port": p[2],
            "tag": p[3],
            "remark": p[4],
            "enable": p[5],
        })
    return rows

def validate_target_inbounds(inbound_ids, protocol=None):
    if not inbound_ids:
        return []

    all_rows = fetch_heimdall_inbounds()
    by_id = {r["id"]: r for r in all_rows}
    missing = [i for i in inbound_ids if i not in by_id]
    if missing:
        die(f"target inbound ids not found in PRIMEVPN: {missing}")

    return [by_id[i] for i in inbound_ids]

def choose_identity(proxy, protocol):
    vless_id = valid_uuid_or_none(get_nested(proxy, "vless", "id"))
    vmess_id = valid_uuid_or_none(get_nested(proxy, "vmess", "id"))

    if protocol == "vmess":
        return vmess_id or vless_id or str(uuid.uuid4()), "vmess.id/vless.id/generated"
    if protocol == "vless":
        return vless_id or vmess_id or str(uuid.uuid4()), "vless.id/vmess.id/generated"

    return vless_id or vmess_id or str(uuid.uuid4()), "vless.id/vmess.id/generated_for_non_uuid_protocol"

def choose_password(proxy, protocol):
    if protocol in {"vless", "vmess"}:
        return token(16), "generated_for_vless_vmess"
    if protocol == "trojan":
        return get_nested(proxy, "trojan", "password") or token(32), "trojan.password/generated"
    if protocol == "shadowsocks":
        return get_nested(proxy, "shadowsocks", "password") or token(32), "shadowsocks.password/generated"
    return token(16), "generated_default"

def choose_auth(proxy, protocol):
    if protocol == "hysteria":
        return get_nested(proxy, "hysteria", "auth") or token(32), "hysteria.auth/generated"
    return token(16), "generated_for_non_hysteria"

def choose_security(proxy, protocol):
    if protocol == "shadowsocks":
        return get_nested(proxy, "shadowsocks", "method") or "chacha20-ietf-poly1305"
    return "auto"

def status_to_enable_and_expiry(status, expire, on_hold_policy):
    st = (status or "").strip().lower()
    expiry_ms, expiry_note = parse_dt_to_ms(expire)
    warnings = []

    if st == "active":
        return True, expiry_ms, expiry_note, warnings

    if st in {"disabled", "expired", "limited"}:
        warnings.append(f"status={st} mapped to enable=false")
        return False, expiry_ms, expiry_note, warnings

    if st == "on_hold":
        warnings.append("PasarGuard status=on_hold detected")
        if on_hold_policy == "disable":
            warnings.append("ON_HOLD_POLICY=disable: imported as disabled")
            return False, 0, "on_hold_disabled", warnings
        if on_hold_policy == "unlimited":
            warnings.append("ON_HOLD_POLICY=unlimited: imported enabled with expiryTime=0")
            return True, 0, "on_hold_unlimited", warnings
        warnings.append("unknown ON_HOLD_POLICY; imported disabled")
        return False, 0, "on_hold_unknown_policy", warnings

    warnings.append(f"unknown status={st}; default mapped to enable=true")
    return True, expiry_ms, expiry_note, warnings

def build_clients(rows, inbound_ids, protocol, on_hold_policy, email_prefix, regenerate_uuids):
    built = []
    report = []
    created_now = now_ms()

    for r in rows:
        proxy = parse_json(r.get("proxy_settings"))
        warnings = []

        pg_data_limit = int(r.get("data_limit") or 0)
        pg_used = int(r.get("used_traffic") or 0)

        if pg_data_limit <= 0:
            hd_total = 0
            traffic_policy = "unlimited"
        else:
            hd_total = max(pg_data_limit - pg_used, 0)
            traffic_policy = "remaining=data_limit-used_traffic"

        identity, identity_source = choose_identity(proxy, protocol)
        if regenerate_uuids:
            old_identity = identity
            identity = str(uuid.uuid4())
            identity_source = identity_source + "/regenerated_from:" + old_identity

        password, password_source = choose_password(proxy, protocol)
        auth, auth_source = choose_auth(proxy, protocol)
        security = choose_security(proxy, protocol)

        enable, expiry_time, expiry_note, status_warnings = status_to_enable_and_expiry(
            r.get("status"),
            r.get("expire"),
            on_hold_policy,
        )
        warnings.extend(status_warnings)

        comment = (r.get("note") or "").strip() or f"Migrated from {r.get('_source_label') or 'PasarGuard'}"
        if (r.get("status") or "").strip().lower() == "on_hold":
            comment = f"{comment} | {r.get('_source_label') or 'PasarGuard'} on_hold"

        if r.get("data_limit_reset_strategy") and r.get("data_limit_reset_strategy") != "no_reset":
            warnings.append(f"{r.get('_source_label') or 'Source'} data_limit_reset_strategy={r.get('data_limit_reset_strategy')} not mapped; PRIMEVPN reset=0")

        target_email = email_prefix + str(r.get("username"))

        client = {
            "email": target_email,
            "sub_id": token(16),
            "uuid": identity,
            "password": password,
            "auth": auth,
            "flow": "",
            "security": security,
            "reverse": "",
            "limit_ip": 0,
            "upload_mbps": 0,
            "download_mbps": 0,
            "total_gb": hd_total,
            "expiry_time": expiry_time,
            "enable": enable,
            "tg_id": 0,
            "group_name": "",
            "comment": comment,
            "reset": 0,
            "owner_admin_id": None,
            "disabled_by_owner_admin_id": None,
            "created_by_admin_id": None,
            "created_at": created_now,
            "updated_at": created_now,
            "wg_private_key": None,
            "wg_public_key": None,
            "wg_allowed_ips": None,
            "wg_pre_shared_key": None,
            "wg_keep_alive": 0,
            "inbound_ids": inbound_ids,
            "traffic_inbound_id": inbound_ids[0] if inbound_ids else 0,
        }

        built.append(client)
        report.append({
            "pasarguard": {
                "id": r.get("id"),
                "username": r.get("username"),
                "status": r.get("status"),
                "data_limit": pg_data_limit,
                "data_limit_human": bytes_human(pg_data_limit),
                "used_traffic": pg_used,
                "used_traffic_human": bytes_human(pg_used),
                "remaining": hd_total,
                "remaining_human": bytes_human(hd_total),
                "traffic_policy": traffic_policy,
                "expire": r.get("expire"),
                "note": r.get("note"),
                "hwid_limit_ignored": r.get("hwid_limit"),
                "data_limit_reset_strategy": r.get("data_limit_reset_strategy"),
            },
            "heimdall": {
                "email": client["email"],
                "uuid": client["uuid"],
                "total_gb": client["total_gb"],
                "total_gb_human": bytes_human(client["total_gb"]),
                "expiry_time": client["expiry_time"],
                "enable": client["enable"],
                "limit_ip": 0,
                "upload_mbps": 0,
                "download_mbps": 0,
                "inbound_ids": inbound_ids,
            },
            "mapping": {
                "protocol": protocol,
                "identity_source": identity_source,
                "password_source": password_source,
                "auth_source": auth_source,
                "expiry_note": expiry_note,
                "traffic_policy": traffic_policy,
                "hwid_policy": "ignored",
                "speed_policy": "upload_mbps=0 download_mbps=0",
                "owner_policy": "owner_admin_id=NULL then x-ui restart/fallback assigns Owner",
            },
            "warnings": warnings,
        })

    return built, report

def check_duplicates(clients):
    if not clients:
        return []

    email_values = ",".join(f"({sql_literal(c['email'])})" for c in clients)
    uuid_values = ",".join(f"({sql_literal(c['uuid'])})" for c in clients)

    sql = f"""
WITH input_emails(email) AS (VALUES {email_values}),
input_uuids(uuid) AS (VALUES {uuid_values})
SELECT 'email|' || c.email || '|' || c.id::text
FROM clients c
JOIN input_emails i ON i.email = c.email
UNION ALL
SELECT 'uuid|' || c.uuid || '|' || c.id::text
FROM clients c
JOIN input_uuids i ON i.uuid = c.uuid
ORDER BY 1;
"""
    out = run_heimdall_psql(sql).strip()
    return out.splitlines() if out else []

def build_insert_sql(clients):
    stmts = [
        "BEGIN;",
        "CREATE TEMP TABLE _yui_imported_clients(client_id bigint, email text, uuid text) ON COMMIT DROP;",
    ]

    for c in clients:
        cols = [
            "email", "sub_id", "uuid", "password", "auth", "flow", "security", "reverse",
            "limit_ip", "upload_mbps", "download_mbps", "total_gb", "expiry_time", "enable",
            "tg_id", "group_name", "comment", "reset",
            "owner_admin_id", "disabled_by_owner_admin_id", "created_by_admin_id",
            "created_at", "updated_at",
            "wg_private_key", "wg_public_key", "wg_allowed_ips", "wg_pre_shared_key", "wg_keep_alive",
        ]
        vals = [sql_literal(c[k]) for k in cols]

        stmts.append(f"""
WITH ins AS (
  INSERT INTO clients ({", ".join(cols)})
  VALUES ({", ".join(vals)})
  RETURNING id, email, uuid
)
INSERT INTO _yui_imported_clients(client_id, email, uuid)
SELECT id, email, uuid FROM ins;
""")

        stmts.append(f"""
INSERT INTO client_traffics (
  inbound_id, enable, email, up, down, expiry_time, total, reset, last_online
)
VALUES (
  {sql_literal(c["traffic_inbound_id"])},
  {sql_literal(c["enable"])},
  {sql_literal(c["email"])},
  0,
  0,
  {sql_literal(c["expiry_time"])},
  {sql_literal(c["total_gb"])},
  {sql_literal(c["reset"])},
  0
)
ON CONFLICT DO NOTHING;
""")

        for inbound_id in c["inbound_ids"]:
            stmts.append(f"""
INSERT INTO client_inbounds (client_id, inbound_id, flow_override, created_at)
SELECT client_id, {int(inbound_id)}, '', {int(c["created_at"])}
FROM _yui_imported_clients
WHERE email = {sql_literal(c["email"])} AND uuid = {sql_literal(c["uuid"])};
""")

    stmts.append("""
-- YUI_SYNC_IMPORTED_CLIENTS_TO_INBOUND_SETTINGS_V1
-- Keep imported relational clients synced into inbounds.settings.clients.
WITH imported_links AS (
    SELECT
        y.client_id,
        c.email,
        c.uuid,
        c.password,
        c.auth,
        c.flow,
        c.security,
        c.enable,
        COALESCE(c.total_gb, 0) AS total_gb,
        COALESCE(c.expiry_time, 0) AS expiry_time,
        COALESCE(c.limit_ip, 0) AS limit_ip,
        COALESCE(c.upload_mbps, 0) AS upload_mbps,
        COALESCE(c.download_mbps, 0) AS download_mbps,
        COALESCE(c.reset, 0) AS reset,
        COALESCE(c.tg_id, 0) AS tg_id,
        COALESCE(c.sub_id, '') AS sub_id,
        COALESCE(c.group_name, '') AS group_name,
        COALESCE(c.comment, '') AS comment,
        COALESCE(c.created_at, floor(extract(epoch from now()) * 1000)::bigint) AS created_at,
        COALESCE(c.updated_at, floor(extract(epoch from now()) * 1000)::bigint) AS updated_at,
        ci.inbound_id
    FROM _yui_imported_clients y
    JOIN clients c ON c.id = y.client_id
    JOIN client_inbounds ci ON ci.client_id = y.client_id
),
missing AS (
    SELECT
        il.inbound_id,
        jsonb_build_object(
            'email', il.email,
            'id', il.uuid,
            'password', COALESCE(NULLIF(il.password, ''), il.uuid, ''),
            'auth', COALESCE(NULLIF(il.auth, ''), il.uuid, ''),
            'flow', COALESCE(il.flow, ''),
            'security', COALESCE(NULLIF(il.security, ''), 'auto'),
            'subId', il.sub_id,
            'enable', il.enable,
            'totalGB', il.total_gb,
            'expiryTime', il.expiry_time,
            'limitIp', il.limit_ip,
            'uploadMbps', il.upload_mbps,
            'downloadMbps', il.download_mbps,
            'reset', il.reset,
            'tgId', il.tg_id,
            'group', il.group_name,
            'comment', il.comment,
            'created_at', il.created_at,
            'updated_at', il.updated_at
        ) AS client_json
    FROM imported_links il
    JOIN inbounds i ON i.id = il.inbound_id
    WHERE NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            COALESCE(NULLIF(i.settings, '')::jsonb -> 'clients', '[]'::jsonb)
        ) AS elem
        WHERE lower(elem ->> 'email') = lower(il.email)
    )
),
by_inbound AS (
    SELECT inbound_id, jsonb_agg(client_json) AS clients_to_add
    FROM missing
    GROUP BY inbound_id
)
UPDATE inbounds i
SET settings = jsonb_set(
    COALESCE(NULLIF(i.settings, '')::jsonb, '{}'::jsonb),
    '{clients}',
    COALESCE(NULLIF(i.settings, '')::jsonb -> 'clients', '[]'::jsonb) || b.clients_to_add,
    true
)::text
FROM by_inbound b
WHERE i.id = b.inbound_id;
""")
    stmts.append("SELECT 'IMPORTED|' || COUNT(*)::text FROM _yui_imported_clients;")
    stmts.append("COMMIT;")
    return "\n".join(stmts)

def backup_heimdall_db():
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S.%fZ")
    bkdir = Path(f"/root/heimdall-backup-before-yui-migration-{ts}")
    bkdir.mkdir(parents=True, exist_ok=True)
    dump = bkdir / "xui-before-yui-migration.dump"

    with dump.open("wb") as f:
        res = subprocess.run(["sudo", "-u", PSQL_USER, "pg_dump", "-Fc", "-d", HEIMDALL_DB], stdout=f, stderr=subprocess.PIPE, cwd="/tmp")

    if res.returncode != 0:
        print(res.stderr.decode(errors="ignore"), file=sys.stderr)
        die("pg_dump failed")

    out, _ = run_cmd(["sha256sum", str(dump)])
    (bkdir / "SHA256SUMS.txt").write_text(out)
    return bkdir

def restart_xui():
    run_cmd(["systemctl", "restart", "x-ui"])
    run_cmd(["sleep", "8"])
    out, _ = run_cmd(["systemctl", "is-active", "x-ui"])
    if out.strip() != "active":
        die("x-ui did not become active after restart")

def verify_imported_clients(clients):
    emails = ",".join(sql_literal(c["email"]) for c in clients)
    sql = f"""
SELECT
  id || '|' ||
  email || '|' ||
  uuid || '|' ||
  enable::text || '|' ||
  total_gb::text || '|' ||
  expiry_time::text || '|' ||
  limit_ip::text || '|' ||
  upload_mbps::text || '|' ||
  download_mbps::text || '|' ||
  COALESCE(owner_admin_id::text,'NULL') || '|' ||
  COALESCE(created_by_admin_id::text,'NULL')
FROM clients
WHERE email IN ({emails})
ORDER BY email;
"""
    return run_heimdall_psql(sql)

def print_inbounds():
    rows = fetch_heimdall_inbounds()
    print()
    print("PRIMEVPN existing inbounds:")
    if not rows:
        print("  No inbounds found. Press Enter for no inbound attachment.")
        return
    for r in rows:
        print(f"  id={r['id']} protocol={r['protocol']} port={r['port']} tag={r['tag']} enable={r['enable']} remark={r['remark']}")

def prompt(default, message):
    suffix = f" [{default}]" if default != "" else ""
    value = input(f"{message}{suffix}: ").strip()
    return default if value == "" else value


def source_summary(rows):
    counts = {}
    total_data_limit = 0
    total_used = 0
    total_remaining = 0

    for r in rows:
        st = str(r.get("status") or "unknown").strip().lower() or "unknown"
        counts[st] = counts.get(st, 0) + 1

        data_limit = int(r.get("data_limit") or 0)
        used = int(r.get("used_traffic") or 0)

        total_data_limit += data_limit
        total_used += used

        if data_limit > 0:
            total_remaining += max(data_limit - used, 0)

    return {
        "total_users": len(rows),
        "status_counts": counts,
        "total_limited_data": total_data_limit,
        "total_used": total_used,
        "total_remaining_limited": total_remaining,
    }

def print_source_summary(rows):
    summary = source_summary(rows)

    print()
    print("Source users summary:")
    print(f"  total users: {summary['total_users']}")

    for status in sorted(summary["status_counts"]):
        print(f"  {status}: {summary['status_counts'][status]}")

    print(f"  limited traffic total: {bytes_human(summary['total_limited_data'])}")
    print(f"  used traffic total: {bytes_human(summary['total_used'])}")
    print(f"  remaining limited traffic: {bytes_human(summary['total_remaining_limited'])}")

def migration_center_provider_menu():
    while True:
        ui_box_header("MIGRATION CENTER")
        ui_title("Select source panel")
        ui_item(1, "PasarGuard")
        ui_item(2, "Marzban")
        ui_item(3, "Hiddify")
        print()
        ui_item(0, "Back")
        ui_rule()

        try:
            choice = ui_input("Choose source panel [0-3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None

        if choice == "1":
            return "pasarguard"
        if choice == "2":
            return "marzban"
        if choice == "3":
            return "hiddify"
        if choice == "0" or choice == "":
            return None

        print()
        print("[ERROR] Invalid option.")

def selected_inbound_protocols(selected_inbounds):
    protocols = []
    for row in selected_inbounds:
        protocol = str(row.get("protocol") or "").strip().lower()
        if protocol and protocol not in protocols:
            protocols.append(protocol)
    return protocols

def detect_protocol_from_selected_inbounds(inbound_ids):
    if not inbound_ids:
        return "vless", []

    selected = validate_target_inbounds(inbound_ids)
    protocols = selected_inbound_protocols(selected)
    primary_protocol = protocols[0] if protocols else "vless"
    return primary_protocol, selected


def normalize_source_adapter_label(source_kind):
    value = str(source_kind or "").strip()

    if value in {"postgres/timescale", "mysql/mariadb"}:
        compose_text = ""
        for path in ["/opt/pasarguard/docker-compose.yml", "/opt/marzban/docker-compose.yml", "./docker-compose.yml"]:
            try:
                compose_text += "\n" + Path(path).read_text().lower()
            except Exception:
                continue

        if value == "postgres/timescale":
            if "timescale/timescaledb" in compose_text or "timescaledb:" in compose_text:
                return "timescaledb"

            if "postgres:" in compose_text or "postgresql:" in compose_text or "image: postgres" in compose_text:
                return "postgresql"

            return "postgresql"

        if value == "mysql/mariadb":
            if "mariadb:" in compose_text or "image: mariadb" in compose_text:
                return "mariadb"

            if "mysql:" in compose_text or "image: mysql" in compose_text:
                return "mysql"

            return "mysql"

    return value

def format_source_adapter(source_kind):
    value = str(source_kind or "").strip()
    if ":" not in value:
        return value

    name, location = value.split(":", 1)
    if not location:
        return value

    return f"{name} => {location}"


def _safe_int(value, default=0):
    try:
        if value in {None, "", "NULL", "\\N"}:
            return default
        return int(value)
    except Exception:
        return default


def _status_summary_text(rows):
    counts = {}

    for r in rows:
        status = str(r.get("status") or "active").strip().lower() or "active"
        counts[status] = counts.get(status, 0) + 1

    if not counts:
        return "none"

    order = ["active", "on_hold", "disabled", "expired", "limited"]
    parts = []

    for key in order:
        if key in counts:
            parts.append(f"{key}={counts.pop(key)}")

    for key in sorted(counts):
        parts.append(f"{key}={counts[key]}")

    return ", ".join(parts)


def _human_source_connection(detected_from):
    raw = str(detected_from or "").strip()

    if raw == "local-mariadb-root-socket":
        return "local MariaDB socket"

    if raw in {"env", "environment"}:
        return "environment"

    if raw.startswith("/"):
        return raw

    return raw or "auto-detected"


def _tree_value(label, value):
    value = "" if value is None else str(value)
    return f"{label}: {value}"


def _clear_screen():
    print("\033[2J\033[3J\033[H", end="")


def print_interactive_overview(panel_label, detected_from, source_kind, rows):
    status_text = _status_summary_text(rows)
    connection_text = _human_source_connection(detected_from)

    print()
    print(f"MIGRATION CENTER / {str(panel_label).upper()}")
    print("═" * 56)
    print()

    print("SOURCE")
    print(f"└─ {panel_label}")
    print("   ├─ Database")
    print(f"   │  ├─ {_tree_value('Connection', connection_text)}")
    print(f"   │  └─ {_tree_value('Adapter', source_kind)}")
    print("   └─ Users")
    print(f"      ├─ {_tree_value('Count', len(rows))}")
    print(f"      └─ {_tree_value('Status', status_text)}")
    print()

    print("HEIMDALL")
    print("└─ Inbounds")

    inbounds = fetch_heimdall_inbounds()

    if not inbounds:
        print("   └─ No inbound found")
    else:
        for idx, inbound in enumerate(inbounds):
            is_last = idx == len(inbounds) - 1
            branch = "└─" if is_last else "├─"
            pipe = "   " if is_last else "│  "

            enable_raw = str(inbound.get("enable") or "").strip().lower()
            status = "enabled" if enable_raw in {"true", "t", "1", "yes", "enabled"} else "disabled"
            tag = inbound.get("remark") or inbound.get("tag") or "-"

            print(f"   {branch} #{inbound.get('id')}")
            print(f"   {pipe}├─ {_tree_value('Protocol', inbound.get('protocol') or '-')}")
            print(f"   {pipe}├─ {_tree_value('Port', inbound.get('port') or '-')}")
            print(f"   {pipe}├─ {_tree_value('Status', status)}")
            print(f"   {pipe}└─ {_tree_value('Tag', tag)}")

    print()
    print("TARGET")
    print("└─ PRIMEVPN inbound selection")

    if inbounds:
        print("   ├─ Single inbound: 1")
        print("   ├─ Multi inbound: 1,2,3")
        print("   ├─ Import without inbound: press Enter")
        print("   └─ Back: 0")
    else:
        print("   ├─ Import without inbound: press Enter")
        print("   └─ Back: 0")

    print()


def interactive_fill(args, detected_url, detected_from):
    panel_label = panel_display_name(args.panel)

    rows, source_kind = load_source_users(args.panel, detected_url, args.user_like)
    source_kind = normalize_source_adapter_label(source_kind)

    # Clear provider menu / previous logs before showing the source overview.
    _clear_screen()

    print_interactive_overview(
        panel_label=panel_label,
        detected_from=detected_from,
        source_kind=source_kind,
        rows=rows,
    )

    raw_inbounds = prompt("", "Target PRIMEVPN inbound IDs")

    if raw_inbounds.strip().lower() in {"0", "back", "b", "q", "exit"}:
        args._interactive_back_to_source_panel = True
        return args

    args._interactive_back_to_source_panel = False
    args.inbounds = raw_inbounds
    inbound_ids = parse_inbound_ids(args.inbounds)

    detected_protocol, selected_inbounds = detect_protocol_from_selected_inbounds(inbound_ids)
    args.protocol = detected_protocol


    return args


def print_interactive_duplicate_summary(dupes):
    email_count = 0
    uuid_count = 0

    for d in dupes:
        text = str(d)
        if text.startswith("email|"):
            email_count += 1
        elif text.startswith("uuid|"):
            uuid_count += 1

    print()
    print("STATUS: stopped")
    print("REASON: duplicate clients already exist in PRIMEVPN")
    print("DETAILS:")

    if email_count:
        print(f"- duplicate emails: {email_count}")

    if uuid_count:
        print(f"- duplicate UUIDs: {uuid_count}")

    if not email_count and not uuid_count:
        print(f"- duplicate records: {len(dupes)}")

    print("NO CHANGES WERE MADE")
    print()
    input("Press Enter to return...")


def main():
    parser = argparse.ArgumentParser(description="Y-UI Migration Center")
    parser.add_argument("--panel", default="pasarguard")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument("--db-url", default="")
    parser.add_argument("--user-like", default="%")
    parser.add_argument("--inbounds", default="")
    parser.add_argument("--protocol", default="vless")
    parser.add_argument("--on-hold-policy", default="disable")
    parser.add_argument("--email-prefix", default="")
    parser.add_argument("--regenerate-uuids", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--no-restart", action="store_true")
    args = parser.parse_args()

    while True:
        if args.interactive:
            args.inbounds = ""
            args.protocol = "vless"
            args.on_hold_policy = "disable"
            args.email_prefix = ""
            args.regenerate_uuids = False
            args._interactive_back_to_source_panel = False

            selected_panel = migration_center_provider_menu()
            if not selected_panel:
                return

            args.panel = selected_panel

        args.panel = str(args.panel or "").strip().lower()

        if args.panel not in {"pasarguard", "marzban", "hiddify"}:
            die(f"unsupported source panel in this build: {args.panel}")

        panel_label = panel_display_name(args.panel)
        panel_slug = args.panel

        try:
            detected_url, detected_from = (args.db_url, "cli --db-url") if args.db_url else detect_source_db_url(args.panel)
        except SystemExit:
            if args.interactive:
                print()
                try:
                    input("Press Enter to go back to Migration Center...")
                except (EOFError, KeyboardInterrupt):
                    pass
                os.system("clear")
                continue
            raise

        if args.interactive:
            args = interactive_fill(args, detected_url, detected_from)

            if getattr(args, "_interactive_back_to_source_panel", False):
                args._interactive_back_to_source_panel = False
                continue

        if not args.interactive:
            ui_box_header("MIGRATION CENTER")
            print(f"PANEL={panel_label}")
            print(f"DETECTED_DB_FROM={detected_from}")
            print(f"DETECTED_DB_URL={mask_db_url(detected_url)}")
            print(f"USER_FILTER={args.user_like}")
            print(f"TARGET_INBOUND_IDS_RAW={args.inbounds!r}")
            print(f"MIGRATION_PROTOCOL={args.protocol}")
            print(f"ON_HOLD_POLICY={args.on_hold_policy}")
            print(f"EMAIL_PREFIX={args.email_prefix!r}")
            print(f"REGENERATE_UUIDS={args.regenerate_uuids}")
            print("SPEED_POLICY=upload_mbps=0 download_mbps=0")
            print("HWID_POLICY=ignored limit_ip=0")
            print()

        validate_heimdall_tables()
        inbound_ids = parse_inbound_ids(args.inbounds)
        inbound_infos = validate_target_inbounds(inbound_ids)

        rows, source_kind = load_source_users(args.panel, detected_url, args.user_like)
        source_kind = normalize_source_adapter_label(source_kind)
        if not args.interactive:
            print(f"SOURCE_ADAPTER={source_kind}")
            print(f"FOUND_USERS={len(rows)}")
            print("TARGET_INBOUNDS=" + (json.dumps(inbound_infos, ensure_ascii=False) if inbound_infos else "NONE"))

        if not rows:
            die(f"no {panel_label} users found")

        clients, report = build_clients(
            rows=rows,
            inbound_ids=inbound_ids,
            protocol=args.protocol,
            on_hold_policy=args.on_hold_policy,
            email_prefix=args.email_prefix,
            regenerate_uuids=args.regenerate_uuids,
        )

        dupes = check_duplicates(clients)

        if dupes:
            if args.interactive:
                print_interactive_duplicate_summary(dupes)
                continue

            print()
            print("DUPLICATES_FOUND:")

            for d in dupes:
                print(d)

            die("duplicates found. Stop before import.")

        if args.interactive:
            print()
            print("STATUS: ready")
            print(f"USERS: {len(clients)}")
            print("TARGET: " + ("no inbound" if not inbound_ids else ",".join(str(x) for x in inbound_ids)))
        else:
            print()
            print("IMPORT_PREVIEW:")

            for c in clients:
                print(
                    f"- {c['email']} uuid={c['uuid']} enable={c['enable']} "
                    f"total={bytes_human(c['total_gb'])} expiry={c['expiry_time']} "
                    f"limit_ip=0 upMbps=0 downMbps=0 inbounds={c['inbound_ids']}"
                )

        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%S.%fZ")
        outdir = Path(f"/root/y-ui-migration-center-{panel_slug}-{ts}")
        outdir.mkdir(parents=True, exist_ok=True)

        sql_text = build_insert_sql(clients)
        (outdir / "clients-preview.json").write_text(json.dumps(clients, ensure_ascii=False, indent=2) + "\n")
        (outdir / "migration-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        (outdir / "import.sql").write_text(sql_text + "\n")

        print()
        print(f"OUTDIR={outdir}")
        print(f"PREVIEW={outdir / 'clients-preview.json'}")
        print(f"REPORT={outdir / 'migration-report.json'}")
        print(f"SQL={outdir / 'import.sql'}")

        if args.dry_run:
            print()
            print("DRY_RUN_OK: no changes were made.")
            return

        if not args.yes:
            print()
            confirm = input("Type YES to backup PRIMEVPN DB and run real import: ").strip()

            if confirm != "YES":
                print("IMPORT_CANCELLED")
                return

        print()
        print("BACKUP_START")
        bkdir = backup_heimdall_db()
        print(f"BACKUP_DIR={bkdir}")

        print()
        print("REAL_IMPORT_START")
        stdout, stderr = run_heimdall_psql_script(sql_text)
        print(stdout)

        if stderr.strip():
            print("STDERR:")
            print(stderr)

        print("REAL_IMPORT_DONE")

        if not args.no_restart:
            print()
            print("RESTART_X_UI_START")
            restart_xui()
            print("RESTART_X_UI_OK")

        print()
        print("VERIFY_IMPORTED_CLIENTS")
        print(verify_imported_clients(clients))
        print("Y_UI_MIGRATION_DONE")
        return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("MIGRATION_CENTER_CANCELLED_BY_USER")
        sys.exit(130)
