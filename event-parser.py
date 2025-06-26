#!/usr/bin/env python3
import argparse
import os
import sqlite3
from datetime import datetime, timedelta
from Evtx.Evtx import Evtx
from xml.etree import ElementTree as ET

# -------------------------------------
# Important events to monitor - Criticality High or Medium to High
# List: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
# and PowerShell Event IDs
# -------------------------------------
DEFAULT_EVENT_IDS = [ 4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124, 1102 ]
POWERSHELL_EVENT_IDS = [800, 4104]

def parse_args():
   parser = argparse.ArgumentParser(description="Parse Windows EVTX logs into SQLite")
   parser.add_argument("--mount", required=True, help="Mounted Windows volume path")
   parser.add_argument("--hostname", required=True, help="Hostname to tag logs")
   parser.add_argument("--restorepoint-id", required=True, help="RestorePoint ID")
   parser.add_argument("--rp-timestamp", required=True, help="RestorePoint timestamp")
   parser.add_argument("--rp-status", required=True, help="RestorePoint malware status")
   parser.add_argument("--db", default="file_index.db", help="SQLite database path")
   parser.add_argument("--logfile", default="Security.evtx", help="Comma-separated EVTX log file names to parse (e.g. 'Security.evtx,Windows PowerShell.evtx'")
   parser.add_argument("--event-ids", help="Comma-separated list of Event IDs to include")
   parser.add_argument("--days", type=int, help="How many days back from restorepoint to include")
   parser.add_argument("--limit", type=int, help="Max number of entries to parse")
   parser.add_argument("--verbose", action="store_true", help="Show debug info")
   return parser.parse_args()

def init_db(path):
   conn = sqlite3.connect(path)
   cur = conn.cursor()
   cur.execute('''
       CREATE TABLE IF NOT EXISTS win_events (
           id INTEGER PRIMARY KEY,
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
   ''')
   cur.execute("CREATE INDEX IF NOT EXISTS idx_event_host_ts ON win_events(hostname, event_id, timestamp)")
   conn.commit()
   conn.close()

def parse_evtx(file_path, hostname, restorepoint_id, rp_timestamp, rp_status, allowed_ids, days_back, limit, verbose):
   events = []
   count = 0
   ns = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}
   rp_dt = datetime.fromisoformat(rp_timestamp)
   start_dt = rp_dt - timedelta(days=days_back) if days_back else None

   with Evtx(file_path) as log:
       for record in log.records():
           try:
               xml = ET.fromstring(record.xml())
               system = xml.find("e:System", ns)
               if system is None:
                   if verbose:
                       print("⚠️ Event has no <System> block, skipping.")
                   continue

               eid_node = system.find("e:EventID", ns)
               if eid_node is None or eid_node.text is None:
                   if verbose:
                       print("⚠️ Event has no valid EventID.")
                   continue

               try:
                   eid = int(eid_node.text.strip())
               except ValueError:
                   if verbose:
                       print("⚠️ Could not convert EventID to int.")
                   continue

               if allowed_ids and eid not in allowed_ids:
                   continue

               timestamp_raw = system.find("e:TimeCreated", ns).attrib.get("SystemTime", "")
               try:
                   timestamp_dt = datetime.fromisoformat(timestamp_raw.replace("+00:00", ""))
               except ValueError:
                   if verbose:
                       print(f"⚠️ Invalid timestamp: {timestamp_raw}")
                   continue

               if start_dt and not (start_dt <= timestamp_dt <= rp_dt):
                   continue

               source = system.find("e:Provider", ns).attrib.get("Name", "")
               level = system.find("e:Level", ns)
               level_map = {"1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose"}
               level_str = level_map.get(level.text, "Unknown") if level is not None else "Unknown"
               message = "".join(xml.itertext())[:1000].strip().replace("\n", " ")

               events.append((
                   hostname, restorepoint_id, rp_timestamp, rp_status,
                   os.path.basename(file_path), eid, level_str, timestamp_raw, source, message
               ))

               count += 1
               if verbose:
                   print(f"[{eid}] {timestamp_raw} - {source} - {level_str}")
               if limit and count >= limit:
                   break

           except Exception as e:
               if verbose:
                   print(f"⚠️ Error parsing event: {e}")
   return events

def store_events(db_path, events):
   conn = sqlite3.connect(db_path)
   cur = conn.cursor()
   inserted_count = 0
   for event in events:
       hostname, restorepoint_id, rp_timestamp, rp_status, logfile, event_id, level, timestamp, source, message = event
       cur.execute('''
           SELECT 1 FROM win_events
           WHERE hostname = ? AND event_id = ? AND timestamp = ? AND source = ? AND message = ?
       ''', (hostname, event_id, timestamp, source, message))
       exists = cur.fetchone()
       if not exists:
           cur.execute('''
               INSERT INTO win_events (
                   hostname, restorepoint_id, rp_timestamp, rp_status,
                   logfile, event_id, level, timestamp, source, message
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ''', event)
           inserted_count += 1
   conn.commit()
   conn.close()
   return inserted_count

# The magic happens here!
def main():
   args = parse_args()
   logfiles = [l.strip() for l in args.logfile.split(",") if l.strip()]

   init_db(args.db)

   all_events = []
   for logfile in logfiles:
       evtx_path = os.path.join(args.mount, "Windows", "System32", "winevt", "Logs", logfile)
       if not os.path.isfile(evtx_path):
           print(f"❌ EVTX file not found: {evtx_path}")
           continue

       if args.verbose:
           print(f"🔍 Parsing {evtx_path}...")

       # PowerShell-spezifische IDs (4104: ScriptBlock logging, 800: Pipeline execution)
       if "PowerShell" in logfile:
           used_ids = [4104, 800]
       else:
           used_ids = [int(e.strip()) for e in args.event_ids.split(",")] if args.event_ids else DEFAULT_EVENT_IDS

       events = parse_evtx(
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
       all_events.extend(events)

   inserted = store_events(args.db, all_events)
   print(f"✓ Parsed and stored {inserted} events into {args.db}")

if __name__ == "__main__":
   main()
