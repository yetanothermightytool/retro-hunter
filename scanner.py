#!/usr/bin/env python3
import argparse
import os
import hashlib
import sqlite3
import multiprocessing
from queue import Empty
from colorama import init, Fore, Style
import csv
import time
import sys
from datetime import datetime
import yara

init(autoreset=True)

CHUNK_SIZE = 50

DEFAULT_EXCLUDES = [
   "Windows\\WinSxS", "Windows\\Temp", "Windows\\SysWOW64",
   "Windows\\System32\\DriverStore", "Windows\\Servicing",
   "ProgramData\\Microsoft\\Windows Defender",
   "ProgramData\\Microsoft\\Windows Defender\\Platform",
   "System Volume Information", "Recovery", "Windows\\Logs",
   "Windows\\SoftwareDistribution\\Download", "Windows\\Prefetch",
   "Program Files\\Common Files\\Microsoft Shared",
   "Windows\\Microsoft.NET\\Framework64", "$Recycle.Bin"
]

CONTENT_FILETYPES = [".txt", ".csv", ".log", ".doc", ".docx", ".pdf", ".rtf"]

def parse_args():
   parser = argparse.ArgumentParser(description="Backup scanner for known bad files")
   parser.add_argument("--mount", required=True)
   parser.add_argument("--workers", type=int, default=max(1, multiprocessing.cpu_count() // 2))
   parser.add_argument("--filetypes")
   parser.add_argument("--maxsize", type=int)
   parser.add_argument("--exclude")
   parser.add_argument("--csv")
   parser.add_argument("--db", help="Path to SQLite database to store findings")
   parser.add_argument("--verbose", action="store_true")
   parser.add_argument("--logfile")
   parser.add_argument("--yara", choices=["off", "all", "suspicious", "content"], default="off")
   parser.add_argument("--hostname")
   parser.add_argument("--restore_point_id")
   parser.add_argument("--rp_timestamp")
   parser.add_argument("--rp_status")
   return parser.parse_args()

def init_db(db_path):
   conn = sqlite3.connect(db_path)
   cur = conn.cursor()
   cur.execute("""
       CREATE TABLE IF NOT EXISTS scan_findings (
           id INTEGER PRIMARY KEY,
           hostname TEXT,
           restore_point_id TEXT,
           rp_timestamp TEXT,
           rp_status TEXT,
           path TEXT,
           sha256 TEXT,
           detection TEXT,
           scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
       )
   """)
   cur.execute("CREATE INDEX IF NOT EXISTS idx_sha256 ON scan_findings(sha256)")
   conn.commit()
   conn.close()

def write_findings_to_db(results, db_path, args):
   conn = sqlite3.connect(db_path)
   cur = conn.cursor()
   inserted = 0
   for path, sha256, detection in results:
       try:
           cur.execute("""
               INSERT INTO scan_findings (
                   hostname, restore_point_id, rp_timestamp, rp_status,
                   path, sha256, detection
               ) VALUES (?, ?, ?, ?, ?, ?, ?)
           """, (
               args.hostname or "",
               args.restore_point_id or "",
               args.rp_timestamp or "",
               args.rp_status or "",
               path,
               sha256 or "",
               detection
           ))
           inserted += 1
       except Exception:
           continue
   conn.commit()
   conn.close()
   return inserted

def log_message(msg, logfile):
   if logfile:
       with open(logfile, "a", encoding="utf-8") as f:
           f.write(f"{datetime.now().isoformat()} {msg}\n")

def get_files(root, filetypes, maxsize, excludes):
   result = []
   normalized_excludes = [ex.lower().replace("/", os.sep).replace("\\", os.sep) for ex in excludes]
   for dirpath, _, files in os.walk(root):
       normalized_dirpath = dirpath.lower().replace("/", os.sep).replace("\\", os.sep)
       if any(ex in normalized_dirpath for ex in normalized_excludes):
           continue
       for name in files:
           path = os.path.join(dirpath, name)
           if filetypes and not any(path.lower().endswith(ft) for ft in filetypes):
               continue
           if maxsize:
               try:
                   if os.path.getsize(path) > maxsize * 1024 * 1024:
                       continue
               except:
                   continue
           result.append(path)
   return result

def sha256_file(path):
   h = hashlib.sha256()
   try:
       with open(path, "rb") as f:
           while chunk := f.read(8192):
               h.update(chunk)
       return h.hexdigest()
   except:
       return None

def load_hashes(db_path="badfiles.db"):
   conn = sqlite3.connect(db_path)
   cur = conn.cursor()
   cur.execute("SELECT sha256, name, standard_path FROM lolbas WHERE sha256 IS NOT NULL")
   badfile_entries = cur.fetchall()
   cur.execute("SELECT sha256, file_name FROM malwarebazaar WHERE sha256 IS NOT NULL")
   malware_entries = cur.fetchall()
   conn.close()
   lolbas_hashes = {sha.lower(): name for sha, name, _ in badfile_entries if sha}
   lolbas_paths = dict((name.lower(), path) for _, name, path in badfile_entries if path)
   malware_hashes = {sha.lower(): name for sha, name in malware_entries if sha}
   return lolbas_hashes, malware_hashes, lolbas_paths

def normalize(p):
   return os.path.normpath(p).replace("\\", os.sep).lower()

def compile_yara_rules(path="yara_rules"):
   rules = {}
   for f in os.listdir(path):
       if f.endswith(".yar") or f.endswith(".yara"):
           rules[f] = os.path.join(path, f)
   return yara.compile(filepaths=rules) if rules else None

def worker(chunk_queue, result_queue, stats_queue, lol_hashes, mw_hashes, lol_paths, yara_rules, yara_mode, verbose, logfile):
   while True:
       try:
           chunk = chunk_queue.get(timeout=5)
       except Empty:
           break
       for path in chunk:
           filename = os.path.basename(path)
           lookup_name = filename.lower()
           norm_path = normalize(path)
           file_hash = sha256_file(path)
           suspicious = False

           if lookup_name in lol_paths:
               expected = normalize(lol_paths[lookup_name])
               try:
                   expected_tail = os.path.normcase(
                       lol_paths[lookup_name].lower().replace("\\", os.sep).replace("/", os.sep)
                   ).split("windows" + os.sep, 1)[-1]
                   actual_path = os.path.normcase(
                       norm_path.lower().replace("\\", os.sep).replace("/", os.sep)
                   )
                   if expected_tail not in actual_path:
                       file_hash = file_hash or sha256_file(path)  # Falls noch nicht berechnet
                       msg = f"⚠️  LOLBAS OUT OF PLACE: {path} (expected {lol_paths[lookup_name]})"
                       print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{msg}")
                       log_message(msg, logfile)
                       result_queue.put((path, file_hash, "lolbas_out_of_place"))  # SHA256 hinzugefügt
                       stats_queue.put("lolbas")
                       suspicious = True
               except Exception as e:
                   print(f"⚠️ LOLBAS check failed for {path}: {e}")

           if file_hash:
               if file_hash in mw_hashes:
                   msg = f"🐞 MATCH (MalwareBazaar) {path} → {mw_hashes[file_hash]}"
                   print(f"\n{Fore.RED}{Style.BRIGHT}{msg}")
                   log_message(msg, logfile)
                   result_queue.put((path, file_hash, mw_hashes[file_hash]))
                   stats_queue.put("hash")
                   suspicious = True
               else:
                   stats_queue.put("clean")
                   if verbose:
                       print(f"\n{Fore.GREEN}✔ CLEAN: {path}")
           else:
               msg = f"⚠️ File not readable: {path}"
               print(f"\n{Fore.YELLOW}{msg}")
               log_message(msg, logfile)
               stats_queue.put("error")

           do_yara = yara_rules and (yara_mode in ("all", "content") or (yara_mode == "suspicious" and suspicious))
           if do_yara:
               print(f"{Fore.BLUE}🔬 YARA scan on: {path}")
               try:
                   matches = yara_rules.match(filepath=path)
                   for match in matches:
                       msg = f"❗ YARA MATCH: {path} → {match.rule}"
                       print(f"\n{Fore.BLUE}{Style.BRIGHT}{msg}")
                       log_message(msg, logfile)
                       result_queue.put((path, file_hash, f"YARA: {match.rule}"))
                       stats_queue.put("yara")
               except Exception as e:
                   msg = f"⚠️ YARA scan failed for {path}: {e}"
                   print(f"\n{Fore.YELLOW}{msg}")
                   log_message(msg, logfile)
       chunk_queue.task_done()

def monitor(stats_queue, total, stop_flag, result_stats):
   start = time.time()
   while not stop_flag.is_set() or not stats_queue.empty():
       time.sleep(5)
       while not stats_queue.empty():
           s = stats_queue.get()
           result_stats[s] = result_stats.get(s, 0) + 1
       scanned = sum(result_stats.values())
       elapsed = time.time() - start
       rate = scanned / elapsed * 60 if elapsed else 0
       remaining = total - scanned
       eta = remaining / (scanned / elapsed) if scanned and elapsed else 0
       percent = (scanned / total) * 100 if total else 0
       sys.stdout.write(
           f"\r⏱️ Scanned: {scanned}/{total} "
           f"| Hash Matches: {result_stats.get('hash', 0)} "
           f"| LOLBAS Out: {result_stats.get('lolbas', 0)} "
           f"| YARA Matches: {result_stats.get('yara', 0)} "
           f"| Errors: {result_stats.get('error', 0)} "
           f"({percent:.1f}%) → {rate:,.0f} files/min | ETA: {time.strftime('%H:%M:%S', time.gmtime(round(eta)))}"
       )
       sys.stdout.flush()
   print()

def main():
   args = parse_args()
   print(f"{Fore.CYAN}[{args.hostname}] 🔍 Scanning: {args.mount}")
   print(f"{Fore.CYAN}[{args.hostname}] ⚙️ Workers: {args.workers}")
   if args.logfile:
       print(f"{Fore.CYAN}[{args.hostname}] 📝 Logging to: {args.logfile}")
   if args.yara != "off":
       print(f"{Fore.CYAN}[{args.hostname}] 🔬 YARA mode: {args.yara}")

   if args.db:
       init_db(args.db)

   filetypes = CONTENT_FILETYPES if args.yara == "content" else (args.filetypes.split(",") if args.filetypes else None)
   excludes = args.exclude.split(",") if args.exclude else DEFAULT_EXCLUDES
   all_files = get_files(args.mount, filetypes, args.maxsize, excludes)
   total = len(all_files)
   if total == 0:
       print(f"{Fore.YELLOW}⚠ No files found to scan. Check filters or exclusions.")
       return

   chunk_queue = multiprocessing.JoinableQueue()
   result_queue = multiprocessing.Queue()
   stats_queue = multiprocessing.Queue()
   result_stats = multiprocessing.Manager().dict()

   for i in range(0, total, CHUNK_SIZE):
       chunk_queue.put(all_files[i:i + CHUNK_SIZE])

   lol_hashes, mw_hashes, lol_paths = load_hashes()
   yara_rules = compile_yara_rules() if args.yara != "off" else None
   stop_flag = multiprocessing.Event()
   monitor_proc = multiprocessing.Process(target=monitor, args=(stats_queue, total, stop_flag, result_stats))
   monitor_proc.start()

   workers = []
   for _ in range(args.workers):
       p = multiprocessing.Process(
           target=worker,
           args=(chunk_queue, result_queue, stats_queue, lol_hashes, mw_hashes, lol_paths, yara_rules, args.yara, args.verbose, args.logfile)
       )
       p.start()
       workers.append(p)

   chunk_queue.join()
   stop_flag.set()
   monitor_proc.join()

   results = []
   while not result_queue.empty():
       results.append(result_queue.get())

   if args.csv and results:
       base, ext = os.path.splitext(args.csv)
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       final_name = f"{base}_{timestamp}{ext}"
       os.makedirs(os.path.dirname(final_name), exist_ok=True)
       with open(final_name, "w", newline="", encoding="utf-8") as f:
           writer = csv.writer(f)
           writer.writerow(["Hostname", "RestorePointID", "RestorePointTime", "RestorePointStatus", "Path", "SHA256", "Detected as"])
           for row in results:
               path, sha256, detection = row
               writer.writerow([
                   args.hostname or "", args.restore_point_id or "", args.rp_timestamp or "",
                   args.rp_status or "", path, sha256 or "", detection
               ])
       print(f"{Fore.YELLOW}💾 Results saved to: {final_name}")

   if args.db and results:
       inserted = write_findings_to_db(results, args.db, args)
       print(f"{Fore.YELLOW}[{args.hostname}] 💾 Inserted {inserted} findings into {args.db}")

   print(f"\n{Fore.GREEN}{Style.BRIGHT}[{args.hostname}] ✅ Scan complete.")
   print(f"{Style.BRIGHT}- Files scanned:       {total}")
   print(f"{Style.BRIGHT}- Malware matches:     {result_stats.get('hash', 0)}")
   print(f"{Style.BRIGHT}- LOLBAS out of place: {result_stats.get('lolbas', 0)}")
   print(f"{Style.BRIGHT}- YARA matches:        {result_stats.get('yara', 0)}")
   print(f"{Style.BRIGHT}- Read errors:         {result_stats.get('error', 0)}")
   print(f"{Style.BRIGHT}- Clean files:         {result_stats.get('clean', 0)}")

if __name__ == "__main__":
   main()
