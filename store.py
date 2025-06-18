#!/usr/bin/env python3
import argparse
import os
import hashlib
import sqlite3
import multiprocessing
from queue import Empty
from datetime import datetime
import stat
from pathlib import Path

CHUNK_SIZE = 500

# Those extents are included in the scan
DEFAULT_BINARY_EXTS = [
  ".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1",
  ".sh", ".bin", ".run", ".so", ".out", ".deb", ".rpm",
  ".jar", ".pyc", ".apk", ".com"
]

# Extents to classify the filetype. Will be stored in the database
EXECUTABLE_EXTS = {'.exe', '.dll', '.bin', '.so', '.elf', '.sh', '.bat', '.cmd', '.ps1', '.apk', '.com'}
SCRIPT_EXTS     = {'.py', '.js', '.vbs', '.pl', '.rb', '.ps1', '.sh', '.bat', '.cmd'}
IMAGE_EXTS      = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tiff'}
DOCUMENT_EXTS   = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf'}
ARCHIVE_EXTS    = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'}

# Classifies the file type based on its extension
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

# Parses command-line arguments and returns them as an object (New approach)
def parse_args():
  parser = argparse.ArgumentParser(description="Index binary files into SQLite")
  parser.add_argument("--mount", required=True, help="Mounted path to scan")
  parser.add_argument("--hostname", required=True, help="Host name (used for DB tagging)")
  parser.add_argument("--restorepoint-id", required=True, help="Veeam RestorePoint ID for traceability")
  parser.add_argument("--rp-timestamp", required=True, help="Restore point timestamp")
  parser.add_argument("--rp-status", required=True, help="Malware status of the restore point")
  parser.add_argument("--workers", type=int, default=max(1, multiprocessing.cpu_count() // 2))
  parser.add_argument("--filetypes", help="Comma-separated list of extensions (e.g. .exe,.dll)")
  parser.add_argument("--maxsize", type=int, help="Max file size in MB")
  parser.add_argument("--exclude", help="Comma-separated directories to exclude (partial paths)")
  parser.add_argument("--db", default="file_index.db", help="Path to SQLite DB")
  parser.add_argument("--verbose", action="store_true", help="Print progress info")
  return parser.parse_args()

# Initializes the SQLite database and creates tables and indexes if needed
def init_db(path):
  conn = sqlite3.connect(path)
  cur = conn.cursor()
  cur.execute('''
      CREATE TABLE IF NOT EXISTS files (
          id INTEGER PRIMARY KEY,
          hostname TEXT,
          restorepoint_id TEXT,
          rp_timestamp TEXT,
          rp_status TEXT,
          path TEXT,
          filename TEXT,
          extension TEXT,
          size INTEGER,
          modified TIMESTAMP,
          created TIMESTAMP,
          sha256 TEXT,
          filetype TEXT,
          is_executable BOOLEAN,
          inserted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(hostname, sha256)
      )
  ''')
  cur.execute("""CREATE INDEX IF NOT EXISTS idx_files_host_filename_sha256_ts ON files(hostname, filename, sha256, rp_timestamp)""")
  cur.execute("""CREATE INDEX IF NOT EXISTS idx_files_host_filename_size_ts ON files(hostname, filename, size, rp_timestamp)""")
  cur.execute("""CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256)""")
  conn.commit()
  conn.close()

# Calculates the SHA-256 hash of a file
def sha256_file(path):
  h = hashlib.sha256()
  try:
      with open(path, "rb") as f:
          while chunk := f.read(8192):
              h.update(chunk)
      return h.hexdigest()
  except:
      return None

# Gets all matching files based on type, size, and exclusion filters (recursive)
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
          except:
              continue
          if maxsize and size > maxsize * 1024 * 1024:
              continue
          if filetypes:
              if ext and ext in filetypes:
                  result.append(full_path)
              elif not ext and os.access(full_path, os.X_OK):
                  result.append(full_path)
          else:
              result.append(full_path)
  return result

# Checks if the file is marked as executable in the file system
def is_executable(path):
  try:
      st = os.stat(path)
      return bool(st.st_mode & stat.S_IXUSR)
  except:
      return False

# Gathers metadata like filename, size, timestamps, hash, and file type for a single file
def extract_metadata(path):
  try:
      stat_result = os.stat(path)
      extension = os.path.splitext(path)[1].lower()
      exec_flag = is_executable(path)
      return {
          "filename": os.path.basename(path),
          "path": os.path.dirname(path),
          "extension": extension,
          "size": stat_result.st_size,
          "modified": datetime.fromtimestamp(stat_result.st_mtime).isoformat(),
          "created": datetime.fromtimestamp(stat_result.st_ctime).isoformat(),
          "is_executable": exec_flag,
          "sha256": sha256_file(path),
          "filetype": detect_filetype(extension, exec_flag)
      }
  except:
      return None

# Hashes and processes each file and sends metadata to result queue.
def worker(chunk_queue, result_queue, hostname, restorepoint_id, rp_timestamp, rp_status):
  while True:
      try:
          chunk = chunk_queue.get(timeout=5)
      except Empty:
          break
      for file_path in chunk:
          meta = extract_metadata(file_path)
          if meta and meta["sha256"]:
              meta["hostname"] = hostname
              meta["restorepoint_id"] = restorepoint_id
              meta["rp_timestamp"] = rp_timestamp
              meta["rp_status"] = rp_status
              result_queue.put(meta)
      chunk_queue.task_done()

# Reads results from the queue and inserts them into the database
def write_results(result_queue, db_path):
  conn = sqlite3.connect(db_path)
  cur = conn.cursor()
  inserted = 0
  while not result_queue.empty():
      meta = result_queue.get()
      try:
          cur.execute('''
              INSERT OR IGNORE INTO files (
                  hostname, restorepoint_id, rp_timestamp, rp_status, path, filename, extension,
                  size, modified, created, sha256, filetype, is_executable
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ''', (
              meta["hostname"], meta["restorepoint_id"], meta["rp_timestamp"], meta["rp_status"], meta["path"],
              meta["filename"], meta["extension"], meta["size"],
              meta["modified"], meta["created"], meta["sha256"],
              meta["filetype"], int(meta["is_executable"])
          ))
          if cur.rowcount:
              inserted += 1
      except Exception as e:
          print(f"❌ Failed to insert {meta} {e}")
  conn.commit()
  conn.close()
  return inserted

# The magic starts here
def main():
  args = parse_args()

  filetypes = (
      [ft.strip().lower() for ft in args.filetypes.split(",")]
      if args.filetypes else DEFAULT_BINARY_EXTS
  )
  excludes = (
      [ex.strip() for ex in args.exclude.split(",")]
      if args.exclude else []
  )

  init_db(args.db)

  print(f"[{args.hostname}] 🔍 Searching for files in {args.mount}...")
  all_files = get_files(args.mount, filetypes, args.maxsize, excludes)
  total = len(all_files)
  print(f"[{args.hostname}] 📦 {total} files matched filters")

  if total == 0:
      return

  chunk_queue = multiprocessing.JoinableQueue()
  result_queue = multiprocessing.Queue()

  for i in range(0, total, CHUNK_SIZE):
      chunk_queue.put(all_files[i:i + CHUNK_SIZE])

  workers = []
  for _ in range(args.workers):
      p = multiprocessing.Process(
          target=worker,
          args=(chunk_queue, result_queue, args.hostname, args.restorepoint_id, args.rp_timestamp, args.rp_status)
      )
      p.start()
      workers.append(p)

  chunk_queue.join()

  if args.verbose:
      print("📥 Writing to database...")

  inserted = write_results(result_queue, args.db)
  print(f"[{args.hostname}] ✅ Done. Indexed {inserted} new files into {args.db}")

if __name__ == "__main__":
  main()
