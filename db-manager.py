#!/usr/bin/env python3
import sqlite3
import argparse
from datetime import datetime, timedelta

def parse_args():
   parser = argparse.ArgumentParser(description="Cleanup old file entries")
   parser.add_argument("--db", default="file_index.db", help="Path to SQLite DB")
   parser.add_argument("--days", type=int, default=90, help="Delete entries older than X days (based on rp_timestamp)")
   parser.add_argument("--dry-run", action="store_true", help="Only show what would be deleted")
   parser.add_argument("--clean-only", action="store_true", help="Only delete non-malicious entries")
   parser.add_argument("--host", help="Optionally restrict cleanup to specific host")
   return parser.parse_args()

def cleanup():
   args = parse_args()
   conn = sqlite3.connect(args.db)
   cur = conn.cursor()

   cutoff = (datetime.now() - timedelta(days=args.days)).strftime("%Y-%m-%d %H:%M:%S")

   query_base = f"SELECT id, sha256, hostname, rp_timestamp FROM files WHERE rp_timestamp < ?"
   params = [cutoff]

   if args.host:
       query_base += " AND hostname = ?"
       params.append(args.host)

   cur.execute(query_base, params)
   rows = cur.fetchall()

   # Count total before filtering
   total = len(rows)

   # Optional filter: keep malware/YARA entries
   if args.clean_only:
       # get malware sha256
       bad_conn = sqlite3.connect("badfiles.db")
       bad_hashes = set()
       for tbl in ["malwarebazaar", "lolbas"]:
           rows_ = bad_conn.execute(f"SELECT sha256 FROM {tbl}").fetchall()
           bad_hashes.update(row[0] for row in rows_)
       bad_conn.close()
       rows = [r for r in rows if r[1] not in bad_hashes]

   to_delete = [r[0] for r in rows]
   malware_hits = total - len(to_delete)

   print(f"📊 Stats for cleanup (cutoff: {cutoff}):")
   print(f"  - Total entries older than {args.days} days: {total}")
   print(f"  - Entries to delete: {len(to_delete)}")
   print(f"  - Malware-protected entries kept: {malware_hits}")

   if not args.dry_run:
       cur.executemany("DELETE FROM files WHERE id = ?", [(i,) for i in to_delete])
       conn.commit()
       print(f"✅ Deleted {len(to_delete)} entries from database.")
       cur.execute("VACUUM")
       print(f"✅ VACCUM to reclaim space.")
   else:
       print("ℹ️ Dry-run mode: no entries deleted.")

   conn.close()

if __name__ == "__main__":
   cleanup()
