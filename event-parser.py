#!/usr/bin/env python3
import argparse
import os
import psycopg2
import psycopg2.extras
from datetime import datetime, timedelta
from typing import List, Tuple, Optional
from contextlib import contextmanager
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET
from dotenv import load_dotenv

load_dotenv(dotenv_path=".env.local")

# Logical event groups to simplify configuration and keep things extensible
EVENT_GROUPS = {
   # Windows Security – baseline (policy and important changes)
   "security_core": [4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124, 1102],
   
   # Windows Security – process activity
   "security_process": [4688, 4689, 4624, 4625, 4634, 4672, 4698, 4699, 4700, 4701, 4702],
   
   # AppLocker
   "applocker_core": [8004, 8007],
   
   # PowerShell – core logging 
   "powershell_core": [4104, 800, 4103, 4105, 4106],
   
   # Sysmon – core telemetry
   "sysmon_core": [1, 2, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 22, 23, 25],
   
   # Reserved for future telemetry 
   "future_extended_telemetry": []
}

def _default_groups_for_logfile(logfile: str) -> List[str]:
   name = logfile.lower()
   if "sysmon" in name:
       return ["sysmon_core"]
   if "powershell" in name:
       return ["powershell_core"]
   if "security" in name:
       return ["security_core"]
   return []

def resolve_event_ids_for_logfile(logfile: str, args) -> Optional[List[int]]:
   if args.event_ids:
       return [int(e.strip()) for e in args.event_ids.split(",") if e.strip()]

   groups = []

   if args.event_groups:
       groups.extend(g.strip() for g in args.event_groups.split(",") if g.strip())
   else:
       groups.extend(_default_groups_for_logfile(logfile))

       if args.extended and "security" in logfile.lower():
           groups.append("security_process")
           groups.append("applocker_core")
   
   if not groups:
       return None

   event_ids = set()
   for g in groups:
       if g not in EVENT_GROUPS:
           available = ", ".join(EVENT_GROUPS.keys())
           raise ValueError(f"Unknown event group '{g}'. Available groups: {available}")
       event_ids.update(EVENT_GROUPS[g])

   return sorted(event_ids)

@contextmanager
def get_db_connection():
   conn = None
   try:
       conn = psycopg2.connect(
           host=os.getenv("POSTGRES_HOST", "localhost"),
           port=os.getenv("POSTGRES_PORT", 5432),
           user=os.getenv("POSTGRES_USER"),
           password=os.getenv("POSTGRES_PASSWORD"),
           dbname=os.getenv("POSTGRES_DB")
       )
       yield conn
   except Exception as e:
       print(f"Database connection error: {e}")
       raise
   finally:
       if conn:
           conn.close()

def init_table(cur):
   cur.execute("""
       CREATE TABLE IF NOT EXISTS win_events (
           id SERIAL PRIMARY KEY,
           hostname TEXT,
           restorepoint_id TEXT,
           rp_timestamp TEXT,
           rp_status TEXT,
           logfile TEXT,
           event_id INTEGER,
           level TEXT,
           timestamp TEXT,
           source TEXT,
           message TEXT
       )
   """)
   cur.execute("CREATE INDEX IF NOT EXISTS idx_event_host_ts ON win_events(hostname, event_id, timestamp)")
   cur.execute("""
       CREATE UNIQUE INDEX IF NOT EXISTS uniq_win_events_entry
       ON win_events(hostname, event_id, timestamp, rp_timestamp)
   """)

def parse_evtx(
   file_path: str,
   hostname: str,
   restorepoint_id: str,
   rp_timestamp: str,
   rp_status: str,
   allowed_ids: Optional[List[int]],
   days_back: Optional[int],
   limit: Optional[int],
   verbose: bool
) -> List[Tuple]:
   events = []
   count = 0
   errors = 0
   ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
   rp_dt = datetime.fromisoformat(rp_timestamp)
   start_dt = rp_dt - timedelta(days=days_back) if days_back else None

   try:
       with Evtx(file_path) as log:
           for record in log.records():
               try:
                   xml = ET.fromstring(record.xml())
                   system = xml.find("e:System", ns)
                   if system is None:
                       continue

                   eid_node = system.find("e:EventID", ns)
                   if eid_node is None or eid_node.text is None:
                       continue

                   eid = int(eid_node.text.strip())
                   if allowed_ids and eid not in allowed_ids:
                       continue

                   timestamp_node = system.find("e:TimeCreated", ns)
                   if timestamp_node is None:
                       continue
                   
                   timestamp_raw = timestamp_node.attrib.get("SystemTime", "")
                   if not timestamp_raw:
                       continue
                   
                   timestamp_raw = timestamp_raw.replace("Z", "+00:00")
                   timestamp_dt = datetime.fromisoformat(timestamp_raw)

                   if start_dt and not (start_dt <= timestamp_dt <= rp_dt):
                       continue

                   provider_node = system.find("e:Provider", ns)
                   source = provider_node.attrib.get("Name", "") if provider_node is not None else ""
                   
                   level_map = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}
                   level_node = system.find("e:Level", ns)
                   level_str = level_map.get(level_node.text, "Unknown") if level_node is not None and level_node.text else "Unknown"
                   
                   message = "".join(xml.itertext())[:2000].strip().replace("\n", " ").replace("\r", " ")

                   events.append((
                       hostname,
                       restorepoint_id,
                       rp_timestamp,
                       rp_status,
                       os.path.basename(file_path),
                       eid,
                       level_str,
                       timestamp_raw,
                       source,
                       message
                   ))

                   count += 1
                   if verbose and count % 1000 == 0:
                       print(f"Processed {count} events...")
                   
                   if limit and count >= limit:
                       break

               except Exception as e:
                   errors += 1
                   if verbose and errors <= 10:
                       print(f"Error parsing event: {e}")
                   continue

   except Exception as e:
       print(f"Error opening EVTX file {file_path}: {e}")
       return []

   if errors > 0:
       print(f"Encountered {errors} parsing errors (skipped)")
   
   return events

def store_events(cur, conn, events: List[Tuple]) -> int:
   if not events:
       print("No events to store")
       return 0

   try:
       psycopg2.extras.execute_batch(
           cur,
           """
           INSERT INTO win_events (
               hostname, restorepoint_id, rp_timestamp, rp_status,
               logfile, event_id, level, timestamp, source, message
           ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
           ON CONFLICT DO NOTHING
           """,
           events,
           page_size=500
       )
       conn.commit()
       inserted = cur.rowcount
       print(f"Inserted {inserted} new events")
       return inserted
   except Exception as e:
       print(f"Error during batch insert: {e}")
       conn.rollback()
       raise

def parse_args():
   parser = argparse.ArgumentParser(description="Parse Windows EVTX logs into PostgreSQL")
   parser.add_argument("--mount", required=True, help="Mounted Windows volume path")
   parser.add_argument("--hostname", required=True, help="Hostname to tag")
   parser.add_argument("--restorepoint-id", required=True, help="Restore point ID")
   parser.add_argument("--rp-timestamp", required=True, help="Restore point timestamp (ISO format)")
   parser.add_argument("--rp-status", required=True, help="Restore point malware status")
   parser.add_argument("--logfile", default="Security.evtx", help="Comma-separated list of EVTX files")
   parser.add_argument("--event-ids", help="Comma-separated list of numeric event IDs (hard override)")
   parser.add_argument("--event-groups", help="Comma-separated logical event groups (e.g. security_core,sysmon_core)")
   parser.add_argument("--days", type=int, help="Only parse events from last N days before restore point")
   parser.add_argument("--limit", type=int, help="Maximum number of events to parse per logfile")
   parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
   parser.add_argument("--extended", action="store_true", help="Include extended Security event IDs")
   return parser.parse_args()

def main():
   args = parse_args()

   print(f"Starting EVTX parsing for {args.hostname}")
   print(f"Mount: {args.mount}")
   print(f"Restore point: {args.restorepoint_id} ({args.rp_timestamp})")

   try:
       with get_db_connection() as conn:
           with conn.cursor() as cur:
               init_table(cur)
               conn.commit()

           logfiles = [l.strip() for l in args.logfile.split(",") if l.strip()]
           all_events = []

           for logfile in logfiles:
               evtx_path = os.path.join(args.mount, "Windows", "System32", "winevt", "Logs", logfile)
               if not os.path.isfile(evtx_path):
                   print(f"EVTX not found: {evtx_path}")
                   continue

               used_ids = resolve_event_ids_for_logfile(logfile, args)

               if args.verbose:
                   if used_ids is None:
                       print(f"No event ID filter applied for {logfile} (processing all events)")
                   else:
                       print(f"Using {len(used_ids)} event IDs for {logfile}: {used_ids}")

               print(f"Parsing {logfile}...")
               parsed = parse_evtx(
                   evtx_path,
                   args.hostname,
                   args.restorepoint_id,
                   args.rp_timestamp,
                   args.rp_status,
                   used_ids,
                   args.days,
                   args.limit,
                   args.verbose
               )
               print(f"Found {len(parsed)} events in {logfile}")
               all_events.extend(parsed)

           with conn.cursor() as cur:
               inserted = store_events(cur, conn, all_events)

           print(f"Scan complete. {inserted} new events stored in database.")

   except Exception as e:
       print(f"Fatal error: {e}")
       return 1

   return 0

if __name__ == "__main__":
   exit(main())
