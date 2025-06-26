import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime

# --- SETTINGS ---
DB_PATH = "file_index.db"
BADFILES_PATH = "badfiles.db"

st.set_page_config(page_title="Retro Hunter - Security Analysis Dashboard", layout="wide")

# --- EVENT ID CLASSIFICATION ---
def classify_event_severity(event_id):
   high_ids = {4104, 4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124}
   medium_high_ids = {800, 1102}
   if event_id in high_ids:
       return "High"
   elif event_id in medium_high_ids:
       return "Medium to High"
   else:
       return "Low"
# --- LOAD FUNCTIONS ---
def load_files():
   try:
       conn = sqlite3.connect(DB_PATH)
       df = pd.read_sql_query("SELECT * FROM files", conn)
       conn.close()
       df["hostname"] = df["hostname"].str.strip().str.lower()
       df["rp_timestamp"] = pd.to_datetime(df["rp_timestamp"], errors="coerce")
       df["rp_status"] = df["rp_status"].fillna("unknown")
       df["inserted_at"] = pd.to_datetime(df.get("inserted_at", None), errors="coerce")
       return df
   except Exception as e:
       st.warning(f"  Could not load Malware Hash Matches {e}")
       return pd.DataFrame()

def load_scan_findings():
   try:
       conn = sqlite3.connect(DB_PATH)
       cursor = conn.cursor()
       cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scan_findings'")
       if not cursor.fetchone():
           st.warning("⚠️ Table 'scan_findings' does not exist yet.")
           return pd.DataFrame()
       df = pd.read_sql_query("""
           SELECT path, sha256, detection AS 'Detection', hostname, rp_timestamp, rp_status, scanned_at
           FROM scan_findings
       """, conn)
       conn.close()
       df["rp_timestamp"] = pd.to_datetime(df["rp_timestamp"], errors="coerce")
       df["scanned_at"] = pd.to_datetime(df["scanned_at"], errors="coerce")
       df["rp_status"] = df["rp_status"].fillna("unknown")
       return df
   except Exception as e:
       st.warning(f"⚠️ Could not load scan findings {e}")
       return pd.DataFrame()

def load_bad_hashes():
   conn = sqlite3.connect(BADFILES_PATH)
   mb = pd.read_sql_query("SELECT sha256, file_name FROM malwarebazaar", conn)
   lol = pd.read_sql_query("SELECT sha256, name, standard_path FROM lolbas", conn)
   conn.close()
   return mb, lol

def load_eventlog_entries():
   try:
       conn = sqlite3.connect(DB_PATH)
       df = pd.read_sql_query("""
           SELECT hostname AS Host,
                  rp_timestamp AS "RP Timestamp",
                  event_id AS "Event ID",
                  level AS Level,
                  timestamp AS "Event Time",
                  source AS Source,
                  message AS Message
           FROM win_events
           WHERE event_id IN (
               4104, 4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124, 1102
           )
           OR event_id IN (550, 800)
           ORDER BY "Event Time" DESC
           LIMIT 100
       """, conn)
       conn.close()
       return df
   except Exception as e:
       st.warning(f"⚠️ Could not load event log entries: {e}")
       return pd.DataFrame()


def enrich_files_with_hits(files_df, scan_df, malware_df):
   files_df["malware_hit"] = files_df["sha256"].isin(malware_df["sha256"])
   files_df["lolbas_hit"] = False
   files_df["yara_hit"] = False

   for _, row in scan_df.iterrows():
       path = row["path"]
       det = str(row["Detection"]).lower()
       if "lolbas" in det:
           files_df.loc[files_df["path"] == path, "lolbas_hit"] = True
       if "yara" in det:
           files_df.loc[files_df["path"] == path, "yara_hit"] = True

   return files_df

def classify_risk(row):
   if row["malware_hit"]:
       return "High"
   elif row["yara_hit"]:
       return "YARA"
   elif row["lolbas_hit"]:
       return "Medium"
   return "Low"

# --- LOAD DATA ---
files_df = load_files()
scan_df = load_scan_findings()
malware_df, lolbas_df = load_bad_hashes()

files_df = enrich_files_with_hits(files_df, scan_df, malware_df)
files_df["Risk Level"] = files_df.apply(classify_risk, axis=1)

# --- FILTER SIDEBAR ---
st.sidebar.title("🔍 Filter")
hostnames = sorted(files_df["hostname"].dropna().unique())
selected_hosts = st.sidebar.multiselect("Hostnames", hostnames, default=hostnames)
date_range = st.sidebar.date_input("Date Range", [])

# --- APPLY FILTERS ---
filtered = files_df[files_df["hostname"].isin(selected_hosts)]
if len(date_range) == 2:
   start, end = pd.to_datetime(date_range[0]), pd.to_datetime(date_range[1])
   filtered = filtered[(filtered["inserted_at"] >= start) & (filtered["inserted_at"] <= end)]
   scan_df = scan_df[(scan_df["scanned_at"] >= start) & (scan_df["scanned_at"] <= end)]

suspicious = filtered[(filtered["malware_hit"]) | (filtered["lolbas_hit"]) | (filtered["yara_hit"])]

malware_files = suspicious["malware_hit"].sum()
if "Detection" in scan_df.columns:
   malware_scan = scan_df["Detection"].str.lower().str.contains("malware", na=False).sum()
   lolbas_scan = scan_df["Detection"].str.lower().str.contains("lolbas", na=False).sum()
   yara_scan = scan_df["Detection"].str.lower().str.contains("yara", na=False).sum()
else:
   malware_scan = 0
   lolbas_scan = 0
   yara_scan = 0

st.markdown("---")
st.markdown("### 🕵🏾‍♀️Retro Hunter - Security Scanner & Threat Audit")

multiuse_query = """
SELECT sha256 FROM files WHERE LOWER(path) NOT LIKE '%/windows/%'
AND LOWER(path) NOT LIKE '%/winsxs/%'
AND LOWER(path) NOT LIKE '%/appdata/%'
AND LOWER(path) NOT LIKE '%/recycle.bin/%'
GROUP BY sha256
HAVING COUNT(DISTINCT filename) > 1
"""
conn = sqlite3.connect(DB_PATH)
multiuse_df = pd.read_sql_query(multiuse_query, conn)
conn.close()
multiuse_total = len(multiuse_df)

col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("🦠 Malware Matches", malware_files + malware_scan)
col2.metric("🛠️ LOLBAS Hits", lolbas_scan)
col3.metric("🔬 YARA Matches", yara_scan)
col4.metric("📂 Total Files", len(filtered))
col5.metric("🌀 Multi-use Hashes", multiuse_total)

# --- EVENT KPI + TABLE ---
conn = sqlite3.connect(DB_PATH)
event_df = pd.read_sql_query("""
  SELECT hostname, event_id, timestamp, source, message
  FROM win_events
  ORDER BY timestamp DESC
""", conn)
conn.close()

event_df["Level"] = event_df["event_id"].apply(classify_event_severity)

# --- WINDOWS SECURITY EVENTLOG KPI SECTION ---
st.markdown("---")
st.markdown("### 🪟 Windows Event Log Analysis")
# Count Events
high_count = event_df[event_df["Level"] == "High"].shape[0]
med_high_count = event_df[event_df["Level"] == "Medium to High"].shape[0]
# Display KPIs
col7, col8 = st.columns(2)
col7.metric("🛑 High Severity Events", high_count)
col8.metric("⚠️ Medium to High Events", med_high_count)


st.markdown("---")
st.markdown("### 📊 Security Reporting Tables")

# Malware Hash Matches
st.markdown("### 🐞 Malware Hash Matches")
comparison_count = len(malware_df)
st.markdown(
   f"<div style='font-size: 0.85em; color: gray;'>Compared against {comparison_count:,} known malware hashes</div>",
   unsafe_allow_html=True
)

if not suspicious.empty:
   suspicious_view = suspicious.rename(columns={
       "hostname": "Host", "filename": "Filename", "path": "Path", "sha256": "SHA-256",
       "inserted_at": "Inserted At", "rp_timestamp": "RP Timestamp", "rp_status": "RP Status"
   })
   suspicious_view["RP Status"] = suspicious_view["RP Status"].str.lower().replace("infected", "🐞 Infected")
   suspicious_view["VT Link"] = suspicious_view["SHA-256"].apply(
       lambda h: f"[🔗](https://www.virustotal.com/gui/file/{h})")
   display_df = suspicious_view.sort_values("Inserted At", ascending=False)[
       ["Host", "Filename", "Path", "Risk Level", "RP Timestamp", "RP Status", "Inserted At", "VT Link"]
   ]
   st.dataframe(display_df, use_container_width=True)
else:
   st.info("No suspicious files found.")

# --- SCAN FINDINGS ---
st.markdown("### 🔍 Scan Findings")
if scan_df.empty:
   st.info("No scan findings available.")
else:
   scan_view = scan_df.rename(columns={
       "hostname": "Host", "path": "Path", "sha256": "SHA-256",
       "rp_timestamp": "RP Timestamp", "rp_status": "RP Status", "scanned_at": "Last Scan"
   })
   st.dataframe(
       scan_view.sort_values("Last Scan", ascending=False)[
           ["Host", "Path", "SHA-256", "Detection", "RP Timestamp", "RP Status", "Last Scan"]
       ],
       use_container_width=True
   )

# --- DEEP ANALYSIS ---
st.markdown("### 📊 Deep Analysis")
def run_analysis_query(title, query):
   conn = sqlite3.connect(DB_PATH)
   df = pd.read_sql_query(query, conn)
   conn.close()
   if df.empty:
       st.info(f"No entries found for: {title}")
   else:
       st.markdown(f"#### {title}")
       st.dataframe(df, use_container_width=True)

run_analysis_query("💣 Large Executables > 50MB", """
   SELECT hostname AS Host, filename AS Filename, path AS Path, ROUND(size / 1048576.0, 2) AS Size_MB
   FROM files
   WHERE filename LIKE '%.exe' AND size > 52428800
""")

run_analysis_query("📁 Suspicious EXEs in AppData", """
   SELECT hostname AS Host, filename AS Filename, path AS Path
   FROM files
   WHERE LOWER(path) LIKE '%appdata%' AND filename LIKE '%.exe'
""")

run_analysis_query("📂 Scripts in Temp/Download Directories", """
   SELECT hostname AS Host, filename AS Filename, path AS Path
   FROM files
   WHERE filetype = 'script' AND (
       LOWER(path) LIKE '%/tmp/%' OR LOWER(path) LIKE '%\\temp\\%' OR LOWER(path) LIKE '%\\downloads\\%'
   )
""")

run_analysis_query("🌀 Multi-use Hashes (Same SHA256, multiple filenames)", """
   SELECT sha256 AS 'SHA-256', path AS 'Path',
          COUNT(DISTINCT filename) AS 'Filename Count',
          GROUP_CONCAT(DISTINCT filename) AS 'Filenames'
   FROM files
   WHERE LOWER(path) NOT LIKE '%/windows/%'
     AND LOWER(path) NOT LIKE '%/winsxs/%'
     AND LOWER(path) NOT LIKE '%/appdata/%'
     AND LOWER(path) NOT LIKE '%/recycle.bin/%'
   GROUP BY sha256
   HAVING COUNT(DISTINCT filename) > 1
""")

run_analysis_query("⚙️ System Process Names Outside System32", """
   SELECT hostname AS Host, filename AS Filename, path AS Path
   FROM files
   WHERE LOWER(filename) IN (
       'lsass.exe', 'services.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'svchost.exe', 'explorer.exe',
       'conhost.exe', 'taskhostw.exe', 'dwm.exe', 'ctfmon.exe', 'spoolsv.exe', 'searchindexer.exe',
       'wuauclt.exe', 'lsm.exe', 'wininit.exe', 'taskeng.exe', 'dllhost.exe', 'rundll32.exe', 'msiexec.exe',
       'sihost.exe', 'fontdrvhost.exe'
   ) AND NOT (
       LOWER(path) LIKE '%/windows/system32%' OR LOWER(path) LIKE '%/windows/winsxs%' OR
       LOWER(path) LIKE '%/windows/servicing/lcu/%' OR LOWER(path) LIKE '%/windows%'
   )
""")

# --- WINDOWS EVENTLOG TABLE ---
st.markdown("---")
st.markdown("### 📑 Windows Event Log Entries")
eventlog_df = load_eventlog_entries()
if not eventlog_df.empty:
   st.dataframe(eventlog_df, use_container_width=True)
else:
   st.info("No relevant Windows Event Log entries found.")

# --- FOOTER ---
st.markdown("---")
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
st.caption(f"🕵🏾‍♀️Retro Hunter – powered by Veeam Data Integration API ({now}) - Version 1.1")
st.caption("🤖 Some logic and optimizations were assisted using AI tools.")
