import os
import pandas as pd
from fastapi import FastAPI, Query, Request, Response, HTTPException
from sqlalchemy import text
from pydantic import BaseModel

from app.db import engine
from app.auth import (
    verify_pw,
    create_token,
    read_token_from_cookie,
    require_role,
    COOKIE_NAME,
    pwd_context,
)

# Do not display /docs 
ENV = os.getenv("ENV", "dev").lower()
IS_PROD = ENV in {"prod"}
app = FastAPI(
   docs_url=None if IS_PROD else "/docs",
   redoc_url=None if IS_PROD else "/redoc",
   openapi_url=None if IS_PROD else "/openapi.json",
)

# Helpers
def classify_event_severity(event_id: int) -> str:
    high_ids = {
        4104, 4618, 4649, 4719, 4765, 4766,
        4794, 4897, 4964, 5124,
        7, 8, 10, 12, 13, 22, 23, 25,
    }
    medium_high_ids = {800, 1102, 1, 3, 11, 16}
    if event_id in high_ids:
        return "High"
    if event_id in medium_high_ids:
        return "Medium to High"
    return "Low"

COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
COOKIE_SAMESITE = os.getenv("COOKIE_SAMESITE", "lax")

# YARA
YARA_TEMPLATE = """
rule Suspicious_{rule_name}
{{
 meta:
     description = "Auto-generated rule for {filename} with high entropy"
     sha256 = "{sha256}"
     created = "{created}"
 strings:
{sections}
 condition:
     uint16(0) == 0x5A4D{size_check}{section_check}
}}
"""

def generate_yara_rule(filename: str, sha256: str, pe_sections: str | None, size: float | int | None):
    from datetime import datetime

    rule_name = (
        str(filename).lower()
        .replace(".", "_")
        .replace("-", "_")
        .replace(" ", "_")
    )[:32]
    created = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S") + " UTC"

    ignore_sections = {".rsrc", ".text", ".data", ".reloc", ".bss", ".edata"}
    bad_sections: list[str] = []

    sections = ""
    section_check = ""

    if pe_sections:
        for sec in [s.strip() for s in str(pe_sections).split(",") if s.strip()]:
            if sec.lower() not in ignore_sections:
                bad_sections.append(sec)

    if not bad_sections:
        return None

    for i, sec in enumerate(bad_sections):
        sections += f'        $section{i+1} = "{sec}"\n'
    section_check = " and any of ($section*)"

    size_check = ""
    try:
        if size is not None:
            s = float(size)
            if s <= 5 * 1024 * 1024:
                size_check = f" and filesize < {int(s) + 1024}"
    except Exception:
        pass

    return YARA_TEMPLATE.format(
        rule_name=rule_name,
        filename=str(filename),
        sha256=str(sha256),
        created=created,
        sections=sections,
        size_check=size_check,
        section_check=section_check,
    )

# Health
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/health/db")
def health_db():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"db": "ok"}

# Authentication
@app.post("/auth/login")
def login(payload: dict, response: Response):
    email = str(payload.get("email", "")).strip().lower()
    password = str(payload.get("password", ""))

    if not email or not password:
        raise HTTPException(status_code=400, detail="email and password required")

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT email, password_hash, role FROM users WHERE email = :email"),
            {"email": email},
        ).mappings().first()

    if not row or not verify_pw(password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Bad credentials")

    token = create_token(row["email"], row["role"])

    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
        max_age=60 * 60 * 12,
    )
    return {"email": row["email"], "role": row["role"]}

@app.post("/auth/logout")
def logout(response: Response):
    response.delete_cookie(key=COOKIE_NAME, path="/")
    return {"ok": True}

@app.get("/auth/me")
def me(request: Request):
    data = read_token_from_cookie(request)
    return {"email": data.get("sub"), "role": data.get("role")}

# Overview
@app.get("/overview/kpis")
def overview_kpis(request: Request):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT
        (SELECT COUNT(*) FROM files) AS total_files,
        (SELECT COUNT(*) FROM files WHERE sha256 IN (SELECT sha256 FROM malwarebazaar)) AS malware_files,
        (SELECT COUNT(*) FROM scan_findings WHERE LOWER(detection) LIKE '%malware%') AS malware_scan,
        (SELECT COUNT(*) FROM scan_findings WHERE LOWER(detection) LIKE '%lolbas%') AS lolbas_hits,
        (SELECT COUNT(*) FROM scan_findings WHERE LOWER(detection) LIKE '%yara%') AS yara_hits
    """

    with engine.connect() as conn:
        row = conn.execute(text(sql)).mappings().first()

    malware_total = int((row["malware_files"] or 0) + (row["malware_scan"] or 0))

    return {
        "malware_matches": malware_total,
        "lolbas_hits": int(row["lolbas_hits"] or 0),
        "yara_matches": int(row["yara_hits"] or 0),
        "total_files": int(row["total_files"] or 0),
    }

@app.get("/overview/suspicious")
def overview_suspicious(
    hostnames: str | None = Query(default=None),
    start: str | None = Query(default=None),
    end: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=5000),
    request: Request = None,
):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    params: dict = {"limit": limit}
    where = []

    if hostnames:
        hosts = [h.strip().lower() for h in hostnames.split(",") if h.strip()]
        if hosts:
            where.append("LOWER(f.hostname) = ANY(:hosts)")
            params["hosts"] = hosts

    if start:
        where.append("f.rp_timestamp >= :start")
        params["start"] = start

    if end:
        where.append("f.rp_timestamp <= :end")
        params["end"] = end

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    sql_cnt = "SELECT COUNT(*) AS cnt FROM public.malwarebazaar"

    sql_items = f"""
    WITH sflags AS (
        SELECT
            path,
            BOOL_OR(LOWER(detection) LIKE '%%lolbas%%') AS lolbas_hit,
            BOOL_OR(LOWER(detection) LIKE '%%yara%%')  AS yara_hit
        FROM scan_findings
        GROUP BY path
    )
    SELECT
        f.hostname AS host,
        f.filename AS filename,
        f.path AS path,
        f.sha256 AS sha256,
        f.rp_timestamp AS rp_timestamp,
        f.rp_status AS rp_status,
        f.inserted_at AS inserted_at,

        (mb.sha256 IS NOT NULL) AS malware_hit,
        COALESCE(sf.lolbas_hit, false) AS lolbas_hit,
        COALESCE(sf.yara_hit,  false) AS yara_hit,

        CASE
            WHEN (mb.sha256 IS NOT NULL) THEN 'High'
            WHEN COALESCE(sf.yara_hit, false) THEN 'YARA'
            WHEN COALESCE(sf.lolbas_hit, false) THEN 'Medium'
            ELSE 'Low'
        END AS risk_level

    FROM files f
    LEFT JOIN public.malwarebazaar mb
        ON mb.sha256 = f.sha256
    LEFT JOIN sflags sf
        ON sf.path = f.path

    {where_sql}
    {"AND" if where_sql else "WHERE"} (
        mb.sha256 IS NOT NULL
        OR COALESCE(sf.lolbas_hit, false)
        OR COALESCE(sf.yara_hit, false)
    )

    ORDER BY f.rp_timestamp DESC NULLS LAST
    LIMIT :limit
    """

    with engine.connect() as conn:
        comparison_cnt = conn.execute(text(sql_cnt)).scalar() or 0
        df = pd.read_sql_query(text(sql_items), conn, params=params)

    df = df.where(pd.notnull(df), None)
    return {
        "comparison_cnt": int(comparison_cnt),
        "count": int(len(df)),
        "items": df.to_dict(orient="records"),
    }

# Scans (Windows + NAS Unstructured)
@app.get("/scan_findings")
def get_scan_findings(limit: int = 200, request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT
        path, sha256, detection, hostname, rp_timestamp, rp_status, scanned_at
    FROM scan_findings
    ORDER BY scanned_at DESC NULLS LAST
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

@app.get("/nas_scan_findings")
def get_nas_scan_findings(limit: int = 200, request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT
        share_name,
        file_path,
        scan_engine,
        detection,
        restore_point_time,
        scanned_at
    FROM nas_scan_findings
    ORDER BY scanned_at DESC NULLS LAST
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

# Events - Windows Event Logs
@app.get("/events")
def get_events(limit: int = 200, request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT hostname, rp_timestamp, event_id, level, timestamp, source, message
    FROM win_events
    ORDER BY timestamp DESC NULLS LAST
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    if not df.empty:
        df["severity"] = df["event_id"].apply(
            lambda x: classify_event_severity(int(x)) if x is not None else "Low"
        )

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

# Deep Analysis
@app.get("/analysis/large-executables")
def analysis_large_executables(limit: int = Query(default=200, ge=1, le=5000), request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT
        hostname AS host,
        filename AS filename,
        path AS path,
        ROUND(size / 1048576.0, 2) AS size_mb
    FROM files
    WHERE filename LIKE '%.exe' AND size > 52428800
    ORDER BY size DESC NULLS LAST
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

@app.get("/analysis/exes-in-appdata")
def analysis_exes_in_appdata(limit: int = Query(default=200, ge=1, le=5000), request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT hostname AS host, filename AS filename, path AS path
    FROM files
    WHERE LOWER(path) LIKE '%appdata%' AND filename LIKE '%.exe'
    ORDER BY rp_timestamp DESC NULLS LAST
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

@app.get("/analysis/scripts-in-temp")
def analysis_scripts_in_temp(limit: int = Query(default=200, ge=1, le=5000), request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT hostname AS host, filename AS filename, path AS path
    FROM files
    WHERE filetype = 'script'
      AND (
        LOWER(path) LIKE '%/tmp/%' OR
        LOWER(path) LIKE '%\\temp\\%' OR
        LOWER(path) LIKE '%\\downloads\\%'
      )
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

@app.get("/analysis/multi-use-hashes")
def analysis_multi_use_hashes(limit: int = Query(default=200, ge=1, le=5000), request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT
        sha256 AS sha256,
        MIN(path) AS path,
        COUNT(DISTINCT filename) AS filename_count,
        STRING_AGG(DISTINCT filename, ', ') AS filenames
    FROM files
    WHERE LOWER(path) NOT LIKE '%/windows/%'
      AND LOWER(path) NOT LIKE '%\\windows\\%'
      AND LOWER(path) NOT LIKE '%/winsxs/%'
      AND LOWER(path) NOT LIKE '%\\winsxs\\%'
      AND LOWER(path) NOT LIKE '%/appdata/%'
      AND LOWER(path) NOT LIKE '%\\appdata\\%'
      AND LOWER(path) NOT LIKE '%recycle.bin%'
    GROUP BY sha256
    HAVING COUNT(DISTINCT filename) > 1
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

@app.get("/analysis/system-process-outside-system32")
def analysis_system_process_outside_system32(limit: int = Query(default=200, ge=1, le=5000), request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT hostname AS host, filename AS filename, path AS path
    FROM files
    WHERE LOWER(filename) IN (
        'lsass.exe','services.exe','winlogon.exe','csrss.exe','smss.exe',
        'svchost.exe','explorer.exe','conhost.exe','taskhostw.exe','dwm.exe',
        'ctfmon.exe','spoolsv.exe','searchindexer.exe','wuauclt.exe',
        'lsm.exe','wininit.exe','taskeng.exe','dllhost.exe','rundll32.exe',
        'msiexec.exe','sihost.exe','fontdrvhost.exe'
    )
    AND NOT (
        LOWER(path) LIKE '%/windows/system32%' OR
        LOWER(path) LIKE '%\\windows\\system32%' OR
        LOWER(path) LIKE '%/windows/winsxs%' OR
        LOWER(path) LIKE '%\\windows\\winsxs%' OR
        LOWER(path) LIKE '%/windows/servicing/lcu/%' OR
        LOWER(path) LIKE '%\\windows\\servicing\\lcu\\%' OR
        LOWER(path) LIKE '%/windows/%' OR
        LOWER(path) LIKE '%\\windows\\%'
    )
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

@app.get("/analysis/high-entropy-suspicious-paths")
def analysis_high_entropy_suspicious_paths(limit: int = Query(default=200, ge=1, le=5000), request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT
        filename AS filename,
        path AS path,
        sha256 AS sha256,
        ROUND(CAST(entropy AS NUMERIC), 2) AS entropy,
        suspicious_structure AS suspicious_structure
    FROM files
    WHERE entropy > 7.5 AND suspicious_structure = 'yes'
    ORDER BY entropy DESC
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

@app.get("/analysis/ifeo-debuggers-suspicious")
def analysis_ifeo_debuggers_suspicious(limit: int = Query(default=200, ge=1, le=5000), request: Request = None):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT
        hostname AS host,
        key_path AS key_path,
        value_name AS value_name,
        value_data AS value_data,
        rp_timestamp AS rp_timestamp
    FROM registry_scan
    WHERE key_path LIKE '%Image File Execution Options%'
      AND value_name = 'Debugger'
      AND (
        value_data LIKE '%cmd.exe%' OR
        value_data LIKE '%powershell.exe%' OR
        value_data LIKE '%wscript.exe%' OR
        value_data LIKE '%cscript.exe%' OR
        value_data LIKE '%\\Users\\%' OR
        value_data LIKE '%\\Temp\\%' OR
        value_data LIKE '%\\AppData\\%' OR
        value_data LIKE '%rat.exe%' OR
        value_data LIKE '%payload%' OR
        value_data LIKE '%\\Tasks\\%' OR
        value_data LIKE '%\\explorer.exe%' OR
        value_data LIKE '%\\svchost.exe%'
      )
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

@app.get("/analysis/high-entropy-recent-pe")
def analysis_high_entropy_recent_pe(
    limit: int = Query(default=200, ge=1, le=5000),
    cutoff: str = Query(default="2024-06-15"),
    request: Request = None,
):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    sql = """
    SELECT
        hostname AS host,
        filename AS filename,
        path AS path,
        rp_timestamp AS rp_timestamp,
        ROUND(CAST(entropy AS NUMERIC), 2) AS entropy,
        magic_type AS magic_type,
        pe_timestamp AS pe_timestamp,
        pe_sections AS pe_sections,
        sha256 AS sha256,
        size AS size
    FROM files
    WHERE filetype = 'executable'
      AND entropy >= 7.9
      AND pe_timestamp >= :cutoff
    ORDER BY entropy DESC
    LIMIT :limit
    """

    with engine.connect() as conn:
        df = pd.read_sql_query(text(sql), conn, params={"limit": limit, "cutoff": cutoff})

    df = df.where(pd.notnull(df), None)
    return {"count": int(len(df)), "items": df.to_dict("records")}

class YaraReq(BaseModel):
    filename: str
    sha256: str
    pe_sections: str | None = None
    size: float | None = None

@app.post("/analysis/yara-rule")
def analysis_yara_rule(data: YaraReq, request: Request):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin", "viewer")

    rule = generate_yara_rule(
        filename=data.filename,
        sha256=data.sha256,
        pe_sections=data.pe_sections,
        size=data.size,
    )
    return {"rule": rule}

# User Management
@app.get("/admin/users")
def list_users(request: Request):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin")

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, email, role, created_at FROM users ORDER BY id")
        ).mappings().all()

    return {"items": [dict(r) for r in rows]}

class CreateUser(BaseModel):
    email: str
    password: str
    role: str

@app.post("/admin/users")
def create_user(data: CreateUser, request: Request):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin")

    email = data.email.strip().lower()
    role = data.role.strip().lower()
    pw = data.password.strip()

    if role not in {"admin", "viewer"}:
        raise HTTPException(status_code=400, detail="invalid role")
    if not email or not pw:
        raise HTTPException(status_code=400, detail="email and password required")

    pw_hash = pwd_context.hash(pw)

    try:
        with engine.begin() as conn:
            conn.execute(
                text("INSERT INTO users (email, password_hash, role) VALUES (:e, :p, :r)"),
                {"e": email, "p": pw_hash, "r": role},
            )
    except Exception:
        raise HTTPException(status_code=400, detail="User already exists")

    return {"status": "ok"}

class UpdateUser(BaseModel):
    role: str | None = None
    password: str | None = None

@app.put("/admin/users/{user_id}")
def update_user(user_id: int, data: UpdateUser, request: Request):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin")

    fields = []
    params = {"id": user_id}

    if data.role is not None:
        role = str(data.role).strip().lower()
        if role:
            if role not in {"admin", "viewer"}:
                raise HTTPException(status_code=400, detail="role must be admin or viewer")
            fields.append("role = :role")
            params["role"] = role

    if data.password is not None:
        pw = str(data.password).strip()
        if pw:
            fields.append("password_hash = :password_hash")
            params["password_hash"] = pwd_context.hash(pw)

    if not fields:
        raise HTTPException(status_code=400, detail="Nothing to update")

    sql = f"UPDATE users SET {', '.join(fields)} WHERE id = :id"

    with engine.begin() as conn:
        result = conn.execute(text(sql), params)
        if result.rowcount != 1:
            raise HTTPException(status_code=404, detail="User not found")

    return {"status": "ok"}

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, request: Request):
    payload = read_token_from_cookie(request)
    require_role(payload, "admin")

    with engine.begin() as conn:
        result = conn.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        if result.rowcount != 1:
            raise HTTPException(status_code=404, detail="User not found")

    return {"status": "ok"}

