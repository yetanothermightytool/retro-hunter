"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../lib/api";
import { DataTable } from "../../components/DataTable";
import { Button } from "../../components/Button";

type ApiList<T> = { count?: number; items: T[] };

type EventRow = {
 hostname?: string;
 host?: string;
 rp_timestamp?: string | null;
 event_id?: number | string | null;
 level?: string | null;
 timestamp?: string | null;
 event_time?: string | null;
 source?: string | null;
 message?: string | null;
 severity?: string | null;
};

function fmt(v: any) {
 if (!v) return "";
 try {
   return new Date(v).toLocaleString();
 } catch {
   return String(v);
 }
}

function toCsv(rows: any[], columns: { key: string; label: string }[]) {
 const esc = (s: any) => {
   const str = s == null ? "" : String(s);
   const needs = /[",\n]/.test(str);
   const quoted = str.replace(/"/g, '""');
   return needs ? `"${quoted}"` : quoted;
 };

 const header = columns.map((c) => esc(c.label)).join(",");
 const body = rows
   .map((r) => columns.map((c) => esc(r?.[c.key])).join(","))
   .join("\n");

 return header + "\n" + body + "\n";
}

function downloadCsv(filename: string, csv: string) {
 const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
 const url = URL.createObjectURL(blob);
 const a = document.createElement("a");
 a.href = url;
 a.download = filename;
 document.body.appendChild(a);
 a.click();
 a.remove();
 URL.revokeObjectURL(url);
}

export default function EventsPage() {
 const [items, setItems] = useState<EventRow[]>([]);
 const [loading, setLoading] = useState(true);

 useEffect(() => {
   async function load() {
     setLoading(true);
     const res = await apiFetch("/events?limit=5000");
     if (res.ok) {
       const json = (await res.json()) as ApiList<EventRow>;
       setItems(json.items ?? []);
     } else {
       setItems([]);
     }
     setLoading(false);
   }
   load();
 }, []);

 const columns = useMemo(
   () => [
     { key: "hostname", label: "Host" },
     { key: "rp_timestamp", label: "RP Timestamp" },
     { key: "event_id", label: "Event ID" },
     { key: "level", label: "Level" },
     { key: "severity", label: "Severity" },
     { key: "timestamp", label: "Event Time" },
     { key: "source", label: "Source" },
     { key: "message", label: "Message" },
   ],
   []
 );

 const view = useMemo(() => {
   const rows = [...items];

   rows.sort((a, b) => {
     const ta = a.timestamp
       ? Date.parse(a.timestamp)
       : a.event_time
       ? Date.parse(a.event_time)
       : 0;
     const tb = b.timestamp
       ? Date.parse(b.timestamp)
       : b.event_time
       ? Date.parse(b.event_time)
       : 0;
     return tb - ta;
   });

   return rows.map((r) => ({
     ...r,
     rp_timestamp: fmt(r.rp_timestamp),
     timestamp: fmt(r.timestamp),
     event_time: fmt(r.event_time),
   }));
 }, [items]);

 if (loading) return <div style={{ padding: 24 }}>Lade…</div>;

 return (
   <div style={{ display: "grid", gap: 16 }}>
     <div>
       <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800 }}>
         📑 Events
       </h1>

       <div style={{ display: "flex", gap: 10, marginTop: 10, flexWrap: "wrap" }}>
         <Button
           onClick={() => downloadCsv("events.csv", toCsv(view, columns))}
           disabled={view.length === 0}
         >
           ⬇️ Download events.csv
         </Button>

         <div style={{ fontSize: 13, opacity: 0.7, alignSelf: "center" }}>
         </div>
       </div>
     </div>

     {view.length === 0 ? (
       <div style={{ opacity: 0.7 }}>No data found!</div>
     ) : (
       <DataTable rows={view} columns={columns} />
     )}
   </div>
 );
}
