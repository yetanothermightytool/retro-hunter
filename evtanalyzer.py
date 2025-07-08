#!/usr/bin/env python3
import sqlite3
import argparse
from datetime import datetime, timedelta
import re

def parse_key_values(message):
   """Extrahiert Schlüssel: Wert-Paare aus dem message-Feld"""
   parsed = {}
   for line in message.splitlines():
       match = re.match(r"\s*([\w\d \-_]+)\s*[:=]\s*(.+)", line)
       if match:
           key = match.group(1).strip()
           value = match.group(2).strip()
           parsed[key] = value
   return parsed

def main():
   parser = argparse.ArgumentParser(description="Analyze parsed Windows event log messages")
   parser.add_argument("--db", default="file_index.db", help="Path to SQLite DB")
   parser.add_argument("--days", type=int, default=7, help="Only include events from last N days")
   parser.add_argument("--limit", type=int, help="Limit number of results")
   args = parser.parse_args()

   since = (datetime.now() - timedelta(days=args.days)).isoformat()

   conn = sqlite3.connect(args.db)
   cur = conn.cursor()

   query = """
       SELECT event_id, timestamp, source, message
       FROM win_events
       WHERE timestamp >= ?
       ORDER BY timestamp DESC
   """
   if args.limit:
       query += f" LIMIT {args.limit}"

   print(f"🔍 Showing events from the last {args.days} days...\n")

   for eid, ts, src, msg in cur.execute(query, (since,)):
       print(f"--- [{ts}] Event ID: {eid} | Source: {src} ---")
       parsed = parse_key_values(msg)
       if parsed:
           for k, v in parsed.items():
               print(f"{k}: {v}")
       else:
           print(msg.strip()[:500])  # fallback auf die rohe message
       print()

   conn.close()

if __name__ == "__main__":
   main()
