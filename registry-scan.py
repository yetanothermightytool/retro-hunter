#!/usr/bin/env python3
import os
import re
import argparse
from datetime import datetime
from typing import List, Tuple
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

from Registry import Registry
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env.local")

# Registry key patterns to be scanned
KEY_PATTERNS = [
   # ---------------------- Code Injection / Execution Hijacking ----------------------
   r".*\\AppCertDlls$",
   r".*\\AppInit_DLLs$",
   r".*\\LoadAppInit_DLLs$",
   r".*\\KnownDlls$",
   r".*\\Image File Execution Options\\.*",
   r".*\\SilentProcessExit\\.*",
   r".*\\Session Manager\\KnownDLLs$",
   r".*\\SessionManager\\AppCertDlls$",

   # ---------------------- Admin, Hacker & Red Team Tools ----------------------
   r".*\\Software\\Sysinternals\\.*",
   r".*\\Software\\ProcessHacker\\.*",
   r".*\\Software\\NirSoft\\.*",
   r".*\\Software\\Microsoft\\Windbg\\.*",
   r".*\\Software\\OllyDbg\\.*",

   # ---------------------- Known Malware / Threat Actor Artefacts ----------------------
   r".*\\Explorer\\Advanced\\Hidden$",
   r".*\\Software\\Classes\\mscfile\\shell\\open\\command$",
   r".*\\Control\\SafeBoot\\.*",
   r".*\\Microsoft\\Windows\\CurrentVersion\\ShellCompatibility\\InboxApp$",
   r".*\\Software\\Classes\\.msc\\.*",
   r".*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell$",

   # ---------------------- ASEPs: Per-user ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\(Load|Run)$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce$",
   r".*\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunonceEx$",

   # ---------------------- ASEPs: System-wide ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run$",

   # ---------------------- RunServices (service startup at boot) ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce$",

   # ---------------------- Boot Execute / Session Manager (additional keys) ----------------------
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\Execute$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\S0InitialCommand$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\SetupExecute$",
   r".*\\System\\CurrentControlSet\\Control\\ServiceControlManagerExtension$",
   r".*\\Winlogon\\Userinit$",
   r".*\\Winlogon\\Shell$",
   r".*\\Session Manager\\PendingFileRenameOperations$",
   r".*\\Control\\Session Manager\\BootExecute$",

   # ---------------------- Startup folder path resolution in Registry ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders$",

   # ---------------------- Network / Remote Access Artefacts ----------------------
   r".*\\Microsoft\\Terminal Server Client\\Servers\\.*",
   r".*\\Network\\Connections\\Pbk$",
   r".*\\Internet Settings$",
   r".*\\Tcpip\\Parameters\\Interfaces\\.*",
   r".*\\NetworkList\\Profiles\\.*",

   # ---------------------- User Activity / Forensic Artefacts ----------------------
   r".*\\UserAssist\\.*",
   r".*\\Explorer\\RecentDocs$",
   r".*\\TypedPaths$",
   r".*\\TypedURLs$",
   r".*\\ComDlg32\\LastVisitedPidlMRU$",
   r".*\\Windows\\CurrentVersion\\Explorer\\RunMRU$",
   r".*\\Windows\\PowerShell\\.*\\ConsoleHost_history$",

   # ---------------------- Services & Drivers ----------------------
   r".*\\Services\\.*",

   # ---------------------- Defensive Evasion / Security Config ----------------------
   r".*\\Windows Defender\\.*",
   r".*\\AeDebug$",

   # ---------------------- COM Hijacking ----------------------
   r".*\\Classes\\CLSID\\.*\\InprocServer32$",
   r".*\\Classes\\CLSID\\.*\\LocalServer32$",

   # ---------------------- Scheduled Tasks (Registry artifacts) ----------------------
   r".*\\Schedule\\TaskCache\\Tree\\.*",
   r".*\\Schedule\\TaskCache\\Tasks\\.*",

   # ---------------------- Miscellaneous ----------------------
   r".*\\MountPoints2\\.*",
   r".*\\Windows\\CurrentVersion\\Uninstall\\.*",
]

COMPILED_PATTERNS = [re.compile(pattern, re.IGNORECASE) for pattern in KEY_PATTERNS]

# Registry hives to scan
HIVES = {
   "SYSTEM": r"Windows/System32/config/SYSTEM",
   "SOFTWARE": r"Windows/System32/config/SOFTWARE",
   "NTUSER": r"Users/{user}/NTUSER.DAT",
}

@contextmanager
def get_db_connection():
   conn = None
   try:
       conn = psycopg2.connect(
           host=os.getenv("POSTGRES_HOST", "localhost"),
           port=os.getenv("POSTGRES_PORT", 5432),
           dbname=os.getenv("POSTGRES_DB"),
           user=os.getenv("POSTGRES_USER"),
           password=os.getenv("POSTGRES_PASSWORD")
       )
       yield conn
   except Exception as e:
       print(f"Database connection error: {e}")
       raise
   finally:
       if conn:
           conn.close()

def init_pg(conn):
   with conn.cursor() as cur:
       cur.execute("""
           CREATE TABLE IF NOT EXISTS registry_scan (
               id SERIAL PRIMARY KEY,
               hostname TEXT,
               restorepoint_id TEXT,
               rp_timestamp TEXT,
               rp_status TEXT,
               hive TEXT,
               key_path TEXT,
               value_name TEXT,
               value_data TEXT,
               last_written TEXT
           )
       """)
       cur.execute("""
           CREATE UNIQUE INDEX IF NOT EXISTS idx_unique_registry_entry
           ON registry_scan(hostname, restorepoint_id, hive, key_path, value_name, value_data)
       """)
       conn.commit()
   print("Database schema initialized")

def match_interesting_key(key_path):
   return any(pattern.search(key_path) for pattern in COMPILED_PATTERNS)

def is_executable_component(value_data):
   return any(ext in value_data.lower() for ext in ['.exe', '.dll', '.sys'])

def parse_hive(hive_path, hive_name, hostname, restorepoint_id, rp_timestamp, rp_status):
   if not os.path.exists(hive_path):
       return []

   results = []

   def walk_keys(key):
       hits = []
       full_path = key.path()
       
       if match_interesting_key(full_path):
           last_written = key.timestamp().isoformat() if key.timestamp() else ""
           
           for val in key.values():
               val_name = val.name()
               try:
                   val_data = str(val.value())
               except Exception:
                   val_data = "<unreadable>"

               if "Services" in full_path and not is_executable_component(val_data):
                   continue

               hits.append((
                   hostname,
                   restorepoint_id,
                   rp_timestamp,
                   rp_status,
                   hive_name,
                   full_path,
                   val_name,
                   val_data,
                   last_written
               ))
       
       try:
           for subkey in key.subkeys():
               hits.extend(walk_keys(subkey))
       except Exception:
           pass
       
       return hits

   try:
       reg = Registry.Registry(hive_path)
       results = walk_keys(reg.root())
       print(f"Parsed {hive_name}: {len(results)} entries")
   except Exception as e:
       print(f"Failed to parse hive {hive_path}: {e}")

   return results

def parse_ntuser_hives(mount_path, hostname, restorepoint_id, rp_timestamp, rp_status, max_workers=4):
   users_dir = os.path.join(mount_path, "Users")
   if not os.path.isdir(users_dir):
       print(f"Users directory not found: {users_dir}")
       return []

   all_hits = []
   user_hives = []

   for user in os.listdir(users_dir):
       user_path = os.path.join(users_dir, user)
       hive_path = os.path.join(user_path, "NTUSER.DAT")
       if os.path.isfile(hive_path):
           user_hives.append((hive_path, f"NTUSER ({user})"))

   print(f"Found {len(user_hives)} user profiles")

   with ThreadPoolExecutor(max_workers=max_workers) as executor:
       futures = {
           executor.submit(
               parse_hive,
               hive_path,
               hive_name,
               hostname,
               restorepoint_id,
               rp_timestamp,
               rp_status
           ): hive_name
           for hive_path, hive_name in user_hives
       }

       for future in as_completed(futures):
           hive_name = futures[future]
           try:
               hits = future.result()
               all_hits.extend(hits)
           except Exception as e:
               print(f"Error processing {hive_name}: {e}")

   return all_hits

def parse_all_hives(mount_path, hostname, restorepoint_id, rp_timestamp, rp_status):
   all_hits = []

   for hive, rel_path in HIVES.items():
       if "{user}" in rel_path:
           continue
       
       hive_path = os.path.join(mount_path, rel_path)
       hits = parse_hive(
           hive_path,
           hive,
           hostname,
           restorepoint_id,
           rp_timestamp,
           rp_status
       )
       all_hits.extend(hits)

   user_hits = parse_ntuser_hives(
       mount_path,
       hostname,
       restorepoint_id,
       rp_timestamp,
       rp_status
   )
   all_hits.extend(user_hits)

   return all_hits

def store_hits_pg(conn, hits):
   if not hits:
       print("No hits to store")
       return 0

   with conn.cursor() as cur:
       try:
           psycopg2.extras.execute_batch(
               cur,
               """
               INSERT INTO registry_scan (
                   hostname, restorepoint_id, rp_timestamp, rp_status,
                   hive, key_path, value_name, value_data, last_written
               ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT DO NOTHING
               """,
               hits,
               page_size=500
           )
           conn.commit()
           inserted = cur.rowcount
           print(f"Inserted {inserted} new entries")
           return inserted
       except Exception as e:
           print(f"Error during batch insert: {e}")
           conn.rollback()
           raise

def parse_args():
   parser = argparse.ArgumentParser(description="Parse Windows Registry hives for security-relevant keys")
   parser.add_argument("--mount", required=True, help="Mounted Windows volume path")
   parser.add_argument("--hostname", required=True, help="Hostname to tag")
   parser.add_argument("--restorepoint-id", required=True, help="Restore point ID")
   parser.add_argument("--rp-timestamp", required=True, help="Restore point timestamp (ISO format)")
   parser.add_argument("--rp-status", required=True, help="Restore point malware status")
   parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers (default: 4)")
   return parser.parse_args()

def main():
   args = parse_args()

   print(f"Starting Registry scan for {args.hostname}")
   print(f"Mount: {args.mount}")
   print(f"Restore point: {args.restorepoint_id} ({args.rp_timestamp})")

   try:
       with get_db_connection() as conn:
           init_pg(conn)

           hits = parse_all_hives(
               args.mount,
               args.hostname,
               args.restorepoint_id,
               args.rp_timestamp,
               args.rp_status
           )

           print(f"Found {len(hits)} total entries")

           inserted = store_hits_pg(conn, hits)
           print(f"Scan complete. {inserted} new entries stored.")

   except Exception as e:
       print(f"Fatal error: {e}")
       return 1

   return 0

if __name__ == "__main__":
   exit(main())
