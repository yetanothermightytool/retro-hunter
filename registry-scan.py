#!/usr/bin/env python3
import os
import re
import logging
import argparse
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed

from Registry import Registry
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env.local")

logging.basicConfig(
   level=logging.INFO,
   format="%(asctime)s [%(levelname)s] %(message)s",
   datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

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

   # ---------------------- RunServices ----------------------
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices$",
   r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices$",
   r".*\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce$",

   # ---------------------- Boot Execute / Session Manager ----------------------
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\Execute$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\S0InitialCommand$",
   r".*\\System\\CurrentControlSet\\Control\\Session Manager\\SetupExecute$",
   r".*\\System\\CurrentControlSet\\Control\\ServiceControlManagerExtension$",
   r".*\\Winlogon\\Userinit$",
   r".*\\Winlogon\\Shell$",
   r".*\\Session Manager\\PendingFileRenameOperations$",
   r".*\\Control\\Session Manager\\BootExecute$",

   # ---------------------- Startup folder path resolution ----------------------
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

   # ---------------------- Scheduled Tasks ----------------------
   r".*\\Schedule\\TaskCache\\Tree\\.*",
   r".*\\Schedule\\TaskCache\\Tasks\\.*",

   # ---------------------- Miscellaneous ----------------------
   r".*\\MountPoints2\\.*",
   r".*\\Windows\\CurrentVersion\\Uninstall\\.*",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in KEY_PATTERNS]

HIVES = {
   "SYSTEM":   r"Windows/System32/config/SYSTEM",
   "SOFTWARE": r"Windows/System32/config/SOFTWARE",
   "NTUSER":   r"Users/{user}/NTUSER.DAT",
}

EXECUTABLE_EXTENSIONS = ('.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.scr')


def safe_mount_path(mount: str) -> str:
   resolved = os.path.realpath(mount)
   if not os.path.isdir(resolved):
       raise ValueError(f"Mount path does not exist or is not a directory: {resolved}")
   return resolved


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
       logger.error(f"Database connection error: {e}")
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
   logger.info("Database schema initialized")


def match_interesting_key(key_path: str) -> bool:
   return any(pattern.search(key_path) for pattern in COMPILED_PATTERNS)


def is_executable_component(value_data: str) -> bool:
   lower = value_data.lower()
   return any(ext in lower for ext in EXECUTABLE_EXTENSIONS)


def walk_keys(key, hostname: str, restorepoint_id: str,
             rp_timestamp: str, rp_status: str, hive_name: str) -> list:
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
           hits.extend(walk_keys(subkey, hostname, restorepoint_id,
                                 rp_timestamp, rp_status, hive_name))
   except Exception:
       pass

   return hits


def parse_hive(hive_path: str, hive_name: str, hostname: str,
              restorepoint_id: str, rp_timestamp: str, rp_status: str) -> list:
   if not os.path.exists(hive_path):
       return []

   try:
       reg = Registry.Registry(hive_path)
       results = walk_keys(reg.root(), hostname, restorepoint_id,
                           rp_timestamp, rp_status, hive_name)
       logger.info(f"Parsed {hive_name}: {len(results)} entries")
   except Exception as e:
       logger.error(f"Failed to parse hive {hive_path}: {e}")
       results = []

   return results


def parse_ntuser_hives(mount_path: str, hostname: str, restorepoint_id: str,
                      rp_timestamp: str, rp_status: str, max_workers: int = 4) -> list:
   users_dir = os.path.join(mount_path, "Users")
   if not os.path.isdir(users_dir):
       logger.warning(f"Users directory not found: {users_dir}")
       return []

   user_hives = []
   for user in os.listdir(users_dir):
       hive_path = os.path.join(users_dir, user, "NTUSER.DAT")
       if os.path.isfile(hive_path):
           user_hives.append((hive_path, f"NTUSER ({user})"))

   logger.info(f"Found {len(user_hives)} user profiles")

   all_hits = []
   with ThreadPoolExecutor(max_workers=max_workers) as executor:
       futures = {
           executor.submit(
               parse_hive, hive_path, hive_name,
               hostname, restorepoint_id, rp_timestamp, rp_status
           ): hive_name
           for hive_path, hive_name in user_hives
       }
       for future in as_completed(futures):
           hive_name = futures[future]
           try:
               all_hits.extend(future.result())
           except Exception as e:
               logger.error(f"Error processing {hive_name}: {e}")

   return all_hits


def parse_all_hives(mount_path: str, hostname: str, restorepoint_id: str,
                   rp_timestamp: str, rp_status: str) -> list:
   all_hits = []

   for hive, rel_path in HIVES.items():
       if "{user}" in rel_path:
           continue
       hive_path = os.path.join(mount_path, rel_path)
       all_hits.extend(parse_hive(hive_path, hive, hostname,
                                  restorepoint_id, rp_timestamp, rp_status))

   all_hits.extend(parse_ntuser_hives(mount_path, hostname,
                                      restorepoint_id, rp_timestamp, rp_status))
   return all_hits


def store_hits_pg(conn, hits: list) -> int:
   if not hits:
       logger.info("No hits to store")
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
           logger.info(
               f"Attempted to insert {len(hits)} entries "
               f"(duplicates skipped via ON CONFLICT DO NOTHING)"
           )
           return len(hits)
       except Exception as e:
           logger.error(f"Error during batch insert: {e}")
           conn.rollback()
           raise


def parse_args() -> argparse.Namespace:
   parser = argparse.ArgumentParser(
       description="Parse Windows Registry hives for security-relevant keys"
   )
   parser.add_argument("--mount",           required=True, help="Mounted Windows volume path")
   parser.add_argument("--hostname",        required=True, help="Hostname to tag")
   parser.add_argument("--restorepoint-id", required=True, help="Restore point ID")
   parser.add_argument("--rp-timestamp",    required=True, help="Restore point timestamp (ISO format)")
   parser.add_argument("--rp-status",       required=True, help="Restore point malware status")
   parser.add_argument("--workers",   type=int, default=4,   help="Parallel workers (default: 4)")
   parser.add_argument("--log-level", default="INFO",
                       choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                       help="Logging verbosity (default: INFO)")
   return parser.parse_args()


def main() -> int:
   args = parse_args()
   logging.getLogger().setLevel(getattr(logging, args.log_level))

   logger.info(f"Starting Registry scan for {args.hostname}")
   logger.info(f"Mount: {args.mount}")
   logger.info(f"Restore point: {args.restorepoint_id} ({args.rp_timestamp})")

   try:
       mount_path = safe_mount_path(args.mount)
   except ValueError as e:
       logger.error(str(e))
       return 1

   try:
       with get_db_connection() as conn:
           init_pg(conn)

           hits = parse_all_hives(
               mount_path,
               args.hostname,
               args.restorepoint_id,
               args.rp_timestamp,
               args.rp_status,
           )

           logger.info(f"Found {len(hits)} total entries")
           store_hits_pg(conn, hits)
           logger.info("Scan complete.")

   except Exception as e:
       logger.error(f"Fatal error: {e}")
       return 1

   return 0


if __name__ == "__main__":
   exit(main())
