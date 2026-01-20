"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../lib/api";
import { DataTable } from "../../components/DataTable";

type ApiList<T> = { count?: number; items: T[] };

type ScanFinding = {
 hostname?: string;
 path?: string;
 sha256?: string;
 detection?: string;
 rp_timestamp?: string | null;
 rp_status?: string | null;
 scanned_at?: string | null;
};

type NasScanFinding = {
 share_name?: string;
 file_path?: string;
 scan_engine?: string;
 detection?: string;
 restore_point_time?: string | null;
 scanned_at?: string | null;
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

export default function ScansPage() {
 const [scanItems, setScanItems] = useState<ScanFinding[]>([]);
 const [nasItems, setNasItems] = useState<NasScanFinding[]>([]);
 const [loading, setLoading] = useState(true);

 useEffect(() => {
   async function load() {
     setLoading(true);

     const [scanRes, nasRes] = await Promise.all([
       apiFetch("/scan_findings?limit=5000"),
       apiFetch("/nas_scan_findings?limit=5000"),
     ]);

     if (scanRes.ok) {
       const data = (await scanRes.json()) as ApiList<ScanFinding>;
       setScanItems(data.items || []);
     } else {
       setScanItems([]);
     }

     if (nasRes.ok) {
       const data = (await nasRes.json()) as ApiList<NasScanFinding>;
       setNasItems(data.items || []);
     } else {
       setNasItems([]);
     }

     setLoading(false);
   }

   load();
 }, []);

 const scanCols = useMemo(
   () => [
     { key: "hostname", label: "Host" },
     { key: "path", label: "Path" },
     { key: "sha256", label: "SHA-256" },
     { key: "detection", label: "Detection" },
     { key: "rp_timestamp", label: "RP Timestamp" },
     { key: "rp_status", label: "RP Status" },
     { key: "scanned_at", label: "Last Scan" },
   ],
   []
 );

 const nasCols = useMemo(
   () => [
     { key: "share_name", label: "Share Name" },
     { key: "file_path", label: "File Path" },
     { key: "scan_engine", label: "Scan Engine" },
     { key: "detection", label: "Detection" },
     { key: "restore_point_time", label: "RP Timestamp" },
     { key: "scanned_at", label: "Last Scan" },
   ],
   []
 );

 const scanView = useMemo(() => {
   // wie Streamlit: sortiert nach Last Scan absteigend (wenn vorhanden)
   const rows = [...scanItems];
   rows.sort((a, b) => {
     const ta = a.scanned_at ? Date.parse(a.scanned_at) : 0;
     const tb = b.scanned_at ? Date.parse(b.scanned_at) : 0;
     return tb - ta;
   });
   return rows.map((r) => ({
     ...r,
     rp_timestamp: fmt(r.rp_timestamp),
     scanned_at: fmt(r.scanned_at),
   }));
 }, [scanItems]);

 const nasView = useMemo(() => {
   const rows = [...nasItems];
   rows.sort((a, b) => {
     const ta = a.scanned_at ? Date.parse(a.scanned_at) : 0;
     const tb = b.scanned_at ? Date.parse(b.scanned_at) : 0;
     return tb - ta;
   });
   return rows.map((r) => ({
     ...r,
     restore_point_time: fmt(r.restore_point_time),
     scanned_at: fmt(r.scanned_at),
   }));
 }, [nasItems]);

 if (loading) return <div style={{ padding: 24 }}>Lade…</div>;

 return (
   <div style={{ display: "grid", gap: 24 }}>
     <div>
       <h1 style={{ fontSize: 28, fontWeight: 900, margin: 0 }}>🔍 Scan Findings</h1>
       <div style={{ display: "flex", gap: 10, marginTop: 10, flexWrap: "wrap" }}>
         <button
           onClick={() =>
             downloadCsv(
               "scans.csv",
               toCsv(scanView, scanCols)
             )
           }
           style={btn}
           disabled={scanView.length === 0}
         >
           ⬇️ Download scans.csv
         </button>
         <div style={{ fontSize: 13, opacity: 0.7, alignSelf: "center" }}>
           {scanView.length.toLocaleString()} rows
         </div>
       </div>
     </div>

     {scanView.length === 0 ? (
       <div style={{ opacity: 0.7 }}>No scan findings found.</div>
     ) : (
       <DataTable rows={scanView} columns={scanCols} />
     )}

     <div style={{ marginTop: 10 }}>
       <h1 style={{ fontSize: 28, fontWeight: 900, margin: 0 }}>📦 Unstructured Data Scan Findings</h1>
       <div style={{ display: "flex", gap: 10, marginTop: 10, flexWrap: "wrap" }}>
         <button
           onClick={() =>
             downloadCsv(
               "nas_scans.csv",
               toCsv(nasView, nasCols)
             )
           }
           style={btn}
           disabled={nasView.length === 0}
         >
           ⬇️ Download nas_scans.csv
         </button>
         <div style={{ fontSize: 13, opacity: 0.7, alignSelf: "center" }}>
           {nasView.length.toLocaleString()} rows
         </div>
       </div>
     </div>

     {nasView.length === 0 ? (
       <div style={{ opacity: 0.7 }}>No unstructured data scan findings found.</div>
     ) : (
       <DataTable rows={nasView} columns={nasCols} />
     )}
   </div>
 );
}

const btn: React.CSSProperties = {
 border: "1px solid #ddd",
 borderRadius: 10,
 padding: "10px 12px",
 background: "transparent",
 cursor: "pointer",
};
