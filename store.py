#!/usr/bin/env python3
import argparse
import os
import hashlib
import psycopg2
import psycopg2.extras
import multiprocessing
from queue import Empty
from datetime import datetime, timezone
import stat
import math
import pefile
import magic
from dotenv import load_dotenv
import signal
from contextlib import contextmanager
import sys
import time

load_dotenv(dotenv_path=".env.local")

CHUNK_SIZE = 500
ENTROPY_READ_SIZE = 204800
MIN_FILESIZE_BYTES = 5 * 1024

DEFAULT_BINARY_EXTS = [".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1",
                     ".sh", ".bin", ".run", ".so", ".out", ".deb", ".rpm",
                     ".jar", ".pyc", ".apk", ".com"]

EXECUTABLE_EXTS = {'.exe', '.dll', '.bin', '.so', '.elf', '.sh', '.bat', '.cmd', '.ps1', '.apk', '.com'}
SCRIPT_EXTS     = {'.py', '.js', '.vbs', '.pl', '.rb', '.ps1', '.sh', '.bat', '.cmd'}
IMAGE_EXTS      = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff'}
DOCUMENT_EXTS   = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf'}
ARCHIVE_EXTS    = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'}

BENIGN_DIRS = ["appdata\\local\\microsoft", "appdata\\local\\google", "syswow64", "windows\\system32",
             "windows\\servicing", "windows\\winsxs", "programdata\\microsoft\\windows defender",
             "appdata\\locallow\\microsoft\\cryptneturlcache", "appdata\\local\\microsoft\\credentials",
             "office\\16.0\\webservicecache"]

SUSPICIOUS_DIRS = ["appdata\\roaming", "appdata\\local\\temp", "downloads", "recycle.bin", "programdata\\temp",
                 "users\\public", "windows\\temp"]

def parse_args():
   parser = argparse.ArgumentParser(description="Index binary files into PostgreSQL")
   parser.add_argument("--mount", required=True)
   parser.add_argument("--hostname", required=True)
   parser.add_argument("--restorepoint-id", required=True)
   parser.add_argument("--rp-timestamp", required=True)
   parser.add_argument("--rp-status", required=True)
   parser.add_argument("--workers", type=int, default=max(1, multiprocessing.cpu_count() // 2))
   parser.add_argument("--filetypes")
   parser.add_argument("--maxsize", type=int)
   parser.add_argument("--exclude")
   parser.add_argument("--verbose", action="store_true")
   return parser.parse_args()

def init_table(conn):
   cur = conn.cursor()
   cur.execute("""
       CREATE TABLE IF NOT EXISTS files (
           id SERIAL PRIMARY KEY,
           hostname TEXT,
           restorepoint_id TEXT,
           rp_timestamp TEXT,
           rp_status TEXT,
           path TEXT,
           filename TEXT,
           extension TEXT,
           size BIGINT,
           modified TIMESTAMPTZ,
           created TIMESTAMPTZ,
           sha256 TEXT,
           filetype TEXT,
           is_executable BOOLEAN,
           entropy REAL,
           suspicious_structure TEXT,
           magic_type TEXT,
           pe_timestamp TEXT,
           pe_sections TEXT,
           inserted_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
           UNIQUE(hostname, sha256)
       );
   """)
   cur.execute("CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256)")
   cur.execute("CREATE INDEX IF NOT EXISTS idx_files_host_filename_sha256_ts ON files(hostname, filename, sha256, rp_timestamp)")
   conn.commit()

@contextmanager
def timeout_context(seconds):
   """Context manager für Timeout bei File-Operations"""
   def timeout_handler(signum, frame):
       raise TimeoutError("Operation timeout")
   
   if hasattr(signal, 'SIGALRM'):
       old_handler = signal.signal(signal.SIGALRM, timeout_handler)
       signal.alarm(seconds)
       try:
           yield
       finally:
           signal.alarm(0)
           signal.signal(signal.SIGALRM, old_handler)
   else:
       yield

def detect_filetype(extension, is_exec=False):
   ext = extension.lower()
   if ext in EXECUTABLE_EXTS or (not ext and is_exec):
       return "executable"
   elif ext in SCRIPT_EXTS:
       return "script"
   elif ext in IMAGE_EXTS:
       return "image"
   elif ext in DOCUMENT_EXTS:
       return "document"
   elif ext in ARCHIVE_EXTS:
       return "archive"
   else:
       return "other"

def calculate_entropy(filepath):
   try:
       with timeout_context(5):
           with open(filepath, 'rb') as f:
               data = f.read(ENTROPY_READ_SIZE)
       if not data:
           return 0.0
       entropy = 0
       for x in range(256):
           p_x = data.count(bytes([x])) / len(data)
           if p_x > 0:
               entropy -= p_x * math.log2(p_x)
       return round(entropy, 2)
   except (TimeoutError, PermissionError, FileNotFoundError, OSError):
       return None

def is_suspicious_structure(file_path):
   file_path = file_path.lower()
   if any(good in file_path for good in BENIGN_DIRS):
       return "no"
   elif any(bad in file_path for bad in SUSPICIOUS_DIRS):
       return "yes"
   return "no"

def enrich_pe_metadata(filepath):
   magic_type, pe_timestamp, pe_sections = None, None, None
   
   try:
       with timeout_context(3):
           magic_type = magic.from_file(filepath)
   except (TimeoutError, Exception):
       pass
   
   try:
       with timeout_context(5):
           pe = pefile.PE(filepath, fast_load=False)
           raw_timestamp = pe.FILE_HEADER.TimeDateStamp
           pe_timestamp = datetime.fromtimestamp(raw_timestamp, timezone.utc).isoformat()
           sections = [s.Name.decode(errors='ignore').strip('\x00') for s in pe.sections]
           pe_sections = ",".join(sections)
   except (TimeoutError, Exception):
       pass
   
   return magic_type, pe_timestamp, pe_sections

def get_files(root, filetypes, maxsize, excludes):
   result = []
   normalized_excludes = [ex.lower().replace("\\", os.sep).replace("/", os.sep) for ex in excludes]
   for dirpath, _, files in os.walk(root):
       norm_dir = dirpath.lower()
       if any(ex in norm_dir for ex in normalized_excludes):
           continue
       for name in files:
           full_path = os.path.join(dirpath, name)
           if not os.path.isfile(full_path):
               continue
           ext = os.path.splitext(name)[1].lower()
           try:
               size = os.path.getsize(full_path)
           except (PermissionError, FileNotFoundError, OSError):
               continue
           if maxsize and size > maxsize * 1024 * 1024:
               continue
           if size < MIN_FILESIZE_BYTES:
               continue
           if filetypes:
               if ext and ext in filetypes:
                   result.append(full_path)
               elif not ext and os.access(full_path, os.X_OK):
                   result.append(full_path)
           else:
               result.append(full_path)
   return result

def is_executable(path):
   try:
       st = os.stat(path)
       return bool(st.st_mode & stat.S_IXUSR)
   except (PermissionError, FileNotFoundError, OSError):
       return False

def sha256_file(path, timeout_seconds=5):

   h = hashlib.sha256()
   try:
       with timeout_context(timeout_seconds):
           with open(path, "rb") as f:
               while chunk := f.read(8192):
                   h.update(chunk)
       return h.hexdigest()
   except (TimeoutError, PermissionError, FileNotFoundError, OSError):
       return None

def extract_metadata(path):
   try:
       stat_result = os.stat(path)
       extension = os.path.splitext(path)[1].lower()
       exec_flag = is_executable(path)
       entropy_val = calculate_entropy(path)
       filetype_val = detect_filetype(extension, exec_flag)
       
       magic_type, pe_timestamp, pe_sections = None, None, None
       if filetype_val == "executable" and extension in {'.exe', '.dll', '.sys'}:
           magic_type, pe_timestamp, pe_sections = enrich_pe_metadata(path)
       
       return {
           "filename": os.path.basename(path),
           "path": os.path.dirname(path),
           "extension": extension,
           "size": stat_result.st_size,
           "modified": datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
           "created": datetime.fromtimestamp(stat_result.st_ctime).isoformat(),
           "is_executable": exec_flag,
           "sha256": sha256_file(path),
           "filetype": filetype_val,
           "entropy": entropy_val,
           "suspicious_structure": is_suspicious_structure(path),
           "magic_type": magic_type,
           "pe_timestamp": pe_timestamp,
           "pe_sections": pe_sections
       }
   except (PermissionError, FileNotFoundError, OSError):
       return None

def worker(chunk_queue, result_queue, stats_queue, hostname, restorepoint_id, rp_timestamp, rp_status):
   while True:
       try:
           chunk = chunk_queue.get(timeout=5)
       except Empty:
           break
       try:
           for file_path in chunk:
               meta = extract_metadata(file_path)
               if meta and meta["sha256"]:
                   meta.update({
                       "hostname": hostname,
                       "restorepoint_id": restorepoint_id,
                       "rp_timestamp": rp_timestamp,
                       "rp_status": rp_status
                   })
                   result_queue.put(meta)
                   stats_queue.put("processed")
               else:
                   stats_queue.put("error")
       finally:
           chunk_queue.task_done()

def collector(result_queue, collected_list, stop_flag):
   while not stop_flag.is_set() or not result_queue.empty():
       try:
           item = result_queue.get(timeout=0.5)
           if item is None:  # Sentinel
               break
           collected_list.append(item)
       except Empty:
           continue

def monitor(stats_queue, total, stop_flag, result_stats):
   start = time.time()
   last_progress = 0
   no_progress_count = 0
   
   while not stop_flag.is_set() or not stats_queue.empty():
       time.sleep(5)
       while not stats_queue.empty():
           s = stats_queue.get()
           result_stats[s] = result_stats.get(s, 0) + 1
       
       processed = sum(result_stats.values())
       elapsed = time.time() - start
       rate = processed / elapsed * 60 if elapsed else 0
       remaining = total - processed
       eta = remaining / (processed / elapsed) if processed and elapsed else 0
       percent = (processed / total) * 100 if total else 0
       
       # Deadlock-Erkennung
       if processed == last_progress:
           no_progress_count += 1
           if no_progress_count >= 6:
               sys.stdout.write(f"\n⚠️  WARNING: No progress for 30s - possible hang!\n")
               sys.stdout.flush()
       else:
           no_progress_count = 0
       last_progress = processed
       
       sys.stdout.write(
           f"\r⏱️  Processed: {processed}/{total} "
           f"| Errors: {result_stats.get('error', 0)} "
           f"({percent:.1f}%) → {rate:,.0f} files/min | ETA: {time.strftime('%H:%M:%S', time.gmtime(round(eta)))}"
       )
       sys.stdout.flush()
   print()

def write_results_batch(results, conn):
   if not results:
       return 0
   
   cur = conn.cursor()
   data = [
       (
           r["hostname"], r["restorepoint_id"], r["rp_timestamp"], r["rp_status"],
           r["path"], r["filename"], r["extension"], r["size"],
           r["modified"], r["created"], r["sha256"], r["filetype"],
           r["is_executable"], r["entropy"], r["suspicious_structure"],
           r["magic_type"], r["pe_timestamp"], r["pe_sections"]
       )
       for r in results
   ]
   
   psycopg2.extras.execute_batch(cur, """
       INSERT INTO files (
           hostname, restorepoint_id, rp_timestamp, rp_status,
           path, filename, extension, size,
           modified, created, sha256, filetype,
           is_executable, entropy, suspicious_structure,
           magic_type, pe_timestamp, pe_sections
       ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
       ON CONFLICT (hostname, sha256) DO NOTHING
   """, data, page_size=1000)
   
   inserted = cur.rowcount
   conn.commit()
   return inserted

def signal_handler(signum, frame, stop_flag, collector_stop):
   print(f"\n⚠️  Received signal {signum}, shutting down gracefully...")
   stop_flag.set()
   collector_stop.set()

def main():
   args = parse_args()
   filetypes = [ft.strip().lower() for ft in args.filetypes.split(",")] if args.filetypes else DEFAULT_BINARY_EXTS
   excludes = [ex.strip() for ex in args.exclude.split(",")] if args.exclude else []

   conn = psycopg2.connect(
       host=os.getenv("POSTGRES_HOST", "localhost"),
       port=os.getenv("POSTGRES_PORT", 5432),
       user=os.getenv("POSTGRES_USER"),
       password=os.getenv("POSTGRES_PASSWORD"),
       dbname=os.getenv("POSTGRES_DB")
   )
   init_table(conn)

   print(f"[{args.hostname}] 🔍 Scanning {args.mount}...")
   all_files = get_files(args.mount, filetypes, args.maxsize, excludes)
   total = len(all_files)
   print(f"[{args.hostname}] 📦 {total} files matching filters")

   if total == 0:
       conn.close()
       return

   chunk_queue = multiprocessing.JoinableQueue()
   result_queue = multiprocessing.Queue(maxsize=5000)
   stats_queue = multiprocessing.Queue()
   manager = multiprocessing.Manager()
   result_stats = manager.dict()
   collected = manager.list()

   for i in range(0, total, CHUNK_SIZE):
       chunk_queue.put(all_files[i:i + CHUNK_SIZE])

   # Start Monitor
   stop_flag = multiprocessing.Event()
   monitor_proc = multiprocessing.Process(target=monitor, args=(stats_queue, total, stop_flag, result_stats))
   monitor_proc.start()

   # Start Collector
   collector_stop = multiprocessing.Event()
   collector_proc = multiprocessing.Process(target=collector, args=(result_queue, collected, collector_stop))
   collector_proc.start()

   # Signal-Handler
   signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, stop_flag, collector_stop))
   signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, stop_flag, collector_stop))

   # Start Workers
   workers = []
   for _ in range(args.workers):
       p = multiprocessing.Process(
           target=worker,
           args=(chunk_queue, result_queue, stats_queue, args.hostname, args.restorepoint_id, args.rp_timestamp, args.rp_status)
       )
       p.start()
       workers.append(p)

   # Wait for completion
   try:
       chunk_queue.join()
   except KeyboardInterrupt:
       print(f"\n⚠️ Interrupted by user")
   
   for p in workers:
       p.join()

   stop_flag.set()
   result_queue.put(None)  # Sentinel
   collector_stop.set()
   monitor_proc.join()
   collector_proc.join()

   while True:
       try:
           item = result_queue.get_nowait()
           if item is not None:
               collected.append(item)
       except Empty:
           break

   results = list(collected)

   if args.verbose:
       print("📥 Writing to database...")

   inserted = write_results_batch(results, conn)
   conn.close()

   print(f"[{args.hostname}] ✅ Done. Indexed {inserted} new files into PostgreSQL.")
   print(f"[{args.hostname}] 📊 Total processed: {result_stats.get('processed', 0)}, Errors: {result_stats.get('error', 0)}")

if __name__ == "__main__":
   main()
