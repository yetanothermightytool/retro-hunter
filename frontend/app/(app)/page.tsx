"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../lib/api";
import { Button } from "../components/Button";

type KPIs = {
 malware_matches: number;
 lolbas_hits: number;
 yara_matches: number;
 total_files: number;
};

type SuspiciousItem = {
 host: string;
 filename: string;
 path: string;
 sha256: string;
 risk_level: string;
 rp_timestamp: string | null;
 rp_status: string | null;
 inserted_at: string | null;
};

function fmt(v: string | null) {
 if (!v) return "";
 const d = new Date(v);
 if (Number.isNaN(d.getTime())) return String(v);
 return d.toLocaleString();
}

function toCsv(items: SuspiciousItem[]) {
 const headers = [
   "Host",
   "Filename",
   "Path",
   "Risk Level",
   "RP Timestamp",
   "RP Status",
   "Inserted At",
   "SHA-256",
   "VT Link",
 ];

 const rows = items.map((r) => [
   r.host ?? "",
   r.filename ?? "",
   r.path ?? "",
   r.risk_level ?? "",
   r.rp_timestamp ?? "",
   r.rp_status ?? "",
   r.inserted_at ?? "",
   r.sha256 ?? "",
   r.sha256 ? `https://www.virustotal.com/gui/file/${r.sha256}` : "",
 ]);

 const esc = (s: string) => {
   const v = String(s ?? "");
   if (/[",\n]/.test(v)) return `"${v.replace(/"/g, '""')}"`;
   return v;
 };

 return [headers, ...rows]
   .map((row) => row.map((c) => esc(String(c))).join(","))
   .join("\n");
}

/* ===== Small UI helpers ===== */

function KpiCard({
 icon,
 label,
 value,
}: {
 icon: string;
 label: string;
 value: number;
}) {
 return (
   <div
     style={{
       border: "1px solid #ddd",
       borderRadius: 12,
       padding: 16,
       display: "flex",
       gap: 12,
       alignItems: "center",
       background: "rgba(255,255,255,0.02)",
     }}
   >
     <div style={{ fontSize: 28, lineHeight: 1 }}>{icon}</div>
     <div>
       <div style={{ fontSize: 22, fontWeight: 800 }}>{value}</div>
       <div style={{ fontSize: 13, opacity: 0.8 }}>{label}</div>
     </div>
   </div>
 );
}

const th: React.CSSProperties = {
 textAlign: "left",
 padding: "10px 12px",
 borderBottom: "1px solid #ddd",
 whiteSpace: "nowrap",
 fontSize: 13,
 opacity: 0.9,
};

const td: React.CSSProperties = {
 padding: "10px 12px",
 borderBottom: "1px solid #eee",
 verticalAlign: "top",
 fontSize: 14,
 whiteSpace: "nowrap",
};

export default function OverviewPage() {
 const [kpis, setKpis] = useState<KPIs | null>(null);
 const [items, setItems] = useState<SuspiciousItem[]>([]);
 const [comparisonCnt, setComparisonCnt] = useState<number>(0);
 const [loading, setLoading] = useState(true);
 const [err, setErr] = useState<string>("");

 useEffect(() => {
   let cancelled = false;

   async function load() {
     setLoading(true);
     setErr("");

     try {
       const [kpiRes, suspRes] = await Promise.all([
         apiFetch("/overview/kpis"),
         apiFetch("/overview/suspicious?limit=200"),
       ]);

       if (!cancelled) {
         if (!kpiRes.ok) {
           setErr(`KPI request failed (${kpiRes.status})`);
         } else {
           setKpis(await kpiRes.json());
         }

         if (suspRes.ok) {
           const data = await suspRes.json();
           setItems(Array.isArray(data.items) ? data.items : []);
           setComparisonCnt(Number(data.comparison_cnt ?? 0));
         } else {
           // Suspicious ist optional – Overview soll trotzdem laden
           setItems([]);
           setComparisonCnt(0);
         }
       }
     } catch (e: any) {
       if (!cancelled) setErr(e?.message || "Failed to load overview");
     } finally {
       if (!cancelled) setLoading(false);
     }
   }

   load();
   return () => {
     cancelled = true;
   };
 }, []);

 const csv = useMemo(() => toCsv(items), [items]);

 if (loading) {
   return <div style={{ padding: 24 }}>Loading…</div>;
 }

 if (!kpis) {
   return (
     <div style={{ padding: 24 }}>
       <h1 style={{ fontSize: 28, fontWeight: 900, margin: 0 }}>
         🕵🏾‍♀️ Retro Hunter – Security Scanner &amp; Threat Audit
       </h1>
       <div style={{ marginTop: 12, opacity: 0.8 }}>
         {err || "No KPI data"}
       </div>
     </div>
   );
 }

 return (
   <div style={{ display: "grid", gap: 24 }}>
     {/* ===== Title ===== */}
     <div>
       <h1 style={{ margin: 0, fontSize: 30, fontWeight: 900 }}>
         🕵🏾‍♀️ Retro Hunter – Security Scanner &amp; Threat Audit
       </h1>
     </div>

     {/* ===== KPIs ===== */}
     <div
       style={{
         display: "grid",
         gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
         gap: 16,
       }}
     >
       <KpiCard icon="🦠" label="Malware Matches" value={kpis.malware_matches} />
       <KpiCard icon="🛠️" label="LOLBAS Hits" value={kpis.lolbas_hits} />
       <KpiCard icon="🔬" label="YARA Matches" value={kpis.yara_matches} />
       <KpiCard icon="📂" label="Total Files" value={kpis.total_files} />
     </div>

     {/* ===== Malware Hash Matches ===== */}
     <div style={{ display: "grid", gap: 12 }}>
       <div>
         <h3 style={{ margin: 0 }}>🐞 Malware Hash Matches</h3>
         <div style={{ fontSize: 13, color: "#888", marginTop: 4 }}>
           Compared against {comparisonCnt.toLocaleString()} known malware hashes
         </div>
       </div>

       {items.length === 0 ? (
         <div style={{ opacity: 0.75 }}>No suspicious files found.</div>
       ) : (
         <>
           <div
             style={{
               display: "flex",
               justifyContent: "flex-end",
               gap: 10,
               flexWrap: "wrap",
             }}
           >
             <Button
               onClick={() => {
                 const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
                 const url = URL.createObjectURL(blob);
                 const a = document.createElement("a");
                 a.href = url;
                 a.download = "suspicious.csv";
                 document.body.appendChild(a);
                 a.click();
                 a.remove();
                 URL.revokeObjectURL(url);
               }}
             >
               ⬇️ Download suspicious.csv
             </Button>
           </div>

           <div style={{ overflowX: "auto", border: "1px solid #ddd", borderRadius: 12 }}>
             <table style={{ width: "100%", borderCollapse: "collapse" }}>
               <thead>
                 <tr>
                   <th style={th}>Host</th>
                   <th style={th}>Filename</th>
                   <th style={th}>Path</th>
                   <th style={th}>Risk Level</th>
                   <th style={th}>RP Timestamp</th>
                   <th style={th}>RP Status</th>
                   <th style={th}>Inserted At</th>
                   <th style={th}>VirusTotal</th>
                 </tr>
               </thead>
               <tbody>
                 {items.map((r, i) => (
                   <tr key={`${r.sha256}-${i}`}>
                     <td style={td}>{r.host}</td>
                     <td style={td}>{r.filename}</td>
                     <td style={{ ...td, maxWidth: 520, overflow: "hidden", textOverflow: "ellipsis" }}>
                       {r.path}
                     </td>
                     <td style={{ ...td, fontWeight: 700 }}>{r.risk_level}</td>
                     <td style={td}>{fmt(r.rp_timestamp)}</td>
                     <td style={td}>{r.rp_status ?? ""}</td>
                     <td style={td}>{fmt(r.inserted_at)}</td>
                     <td style={td}>
                       {r.sha256 ? (
                         <a
                           href={`https://www.virustotal.com/gui/file/${r.sha256}`}
                           target="_blank"
                           rel="noreferrer"
                         >
                           Open in VirusTotal
                         </a>
                       ) : (
                         ""
                       )}
                     </td>
                   </tr>
                 ))}
               </tbody>
             </table>
           </div>
         </>
       )}

       {err ? <div style={{ color: "#b00020" }}>{err}</div> : null}
     </div>
   </div>
 );
}
