"use client";
 
import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../lib/api";
import { DataTable } from "../../components/DataTable";
import { Button } from "../../components/Button";

type Row = Record<string, any>;

type BlockState = {
 loading: boolean;
 items: Row[];
 error?: string;
};

function toCsv(items: Row[], columns: { key: string; label: string }[]) {
 if (!items?.length) return "";
 const esc = (v: any) => {
   const str = v === null || v === undefined ? "" : String(v);
   const needs = /[",\n]/.test(str);
   const safe = str.replaceAll('"', '""');
   return needs ? `"${safe}"` : safe;
 };
 const head = columns.map((c) => esc(c.label)).join(",");
 const body = items
   .map((r) => columns.map((c) => esc(r?.[c.key])).join(","))
   .join("\n");
 return `${head}\n${body}\n`;
}

function downloadText(filename: string, text: string, mime = "text/csv") {
 const blob = new Blob([text], { type: mime });
 const url = URL.createObjectURL(blob);
 const a = document.createElement("a");
 a.href = url;
 a.download = filename;
 document.body.appendChild(a);
 a.click();
 a.remove();
 URL.revokeObjectURL(url);
}

async function loadBlock(path: string): Promise<Row[]> {
 const res = await apiFetch(path);
 if (!res.ok) {
   const msg = await res.text().catch(() => "");
   throw new Error(`${res.status} ${res.statusText} ${msg}`.trim());
 }
 const data = await res.json();
 return data.items || [];
}

export default function DeepAnalysisPage() {
 const [loadingAll, setLoadingAll] = useState(true);

 const [largeExes, setLargeExes] = useState<BlockState>({ loading: true, items: [] });
 const [exesAppData, setExesAppData] = useState<BlockState>({ loading: true, items: [] });
 const [scriptsTemp, setScriptsTemp] = useState<BlockState>({ loading: true, items: [] });
 const [multiHashes, setMultiHashes] = useState<BlockState>({ loading: true, items: [] });
 const [sysOutside, setSysOutside] = useState<BlockState>({ loading: true, items: [] });
 const [entropySusp, setEntropySusp] = useState<BlockState>({ loading: true, items: [] });
 const [ifeo, setIfeo] = useState<BlockState>({ loading: true, items: [] });
 const [recentPe, setRecentPe] = useState<BlockState>({ loading: true, items: [] });

 const [yaraSelected, setYaraSelected] = useState<string>("");
 const [yaraRule, setYaraRule] = useState<string>("");
 const [yaraBusy, setYaraBusy] = useState(false);
 const [yaraMsg, setYaraMsg] = useState<string>("");

 // ---- Column definitions (pro Block) ----
 const colsLargeExes = useMemo(
   () => [
     { key: "host", label: "Host" },
     { key: "filename", label: "Filename" },
     { key: "path", label: "Path" },
     { key: "size_mb", label: "Size (MB)" },
   ],
   []
 );

 const colsAppData = useMemo(
   () => [
     { key: "host", label: "Host" },
     { key: "filename", label: "Filename" },
     { key: "path", label: "Path" },
   ],
   []
 );

 const colsScripts = useMemo(
   () => [
     { key: "host", label: "Host" },
     { key: "filename", label: "Filename" },
     { key: "path", label: "Path" },
   ],
   []
 );

 const colsMultiHashes = useMemo(
   () => [
     { key: "sha256", label: "SHA-256" },
     { key: "filename_count", label: "Filename Count" },
     { key: "filenames", label: "Filenames" },
   ],
   []
 );

 const colsSysOutside = useMemo(
   () => [
     { key: "host", label: "Host" },
     { key: "filename", label: "Filename" },
     { key: "path", label: "Path" },
   ],
   []
 );

 const colsEntropySusp = useMemo(
   () => [
     { key: "filename", label: "Filename" },
     { key: "path", label: "Path" },
     { key: "sha256", label: "SHA-256" },
     { key: "entropy", label: "Entropy" },
     { key: "suspicious_structure", label: "Suspicious Path" },
   ],
   []
 );

 const colsIfeo = useMemo(
   () => [
     { key: "host", label: "Host" },
     { key: "key_path", label: "Key Path" },
     { key: "value_name", label: "Value Name" },
     { key: "value_data", label: "Value Data" },
     { key: "rp_timestamp", label: "RP Timestamp" },
   ],
   []
 );

 const colsRecentPe = useMemo(
   () => [
     { key: "hostname", label: "Host" }, // backend liefert evtl hostname
     { key: "host", label: "Host" },     // fallback falls backend host liefert
     { key: "filename", label: "Filename" },
     { key: "path", label: "Path" },
     { key: "rp_timestamp", label: "RP Timestamp" },
     { key: "entropy", label: "Entropy" },
     { key: "magic_type", label: "Magic Type" },
     { key: "pe_timestamp", label: "PE Timestamp" },
     { key: "pe_sections", label: "PE Sections" },
     { key: "sha256", label: "SHA-256" },
   ],
   []
 );

 useEffect(() => {
   let alive = true;

   async function run() {
     setLoadingAll(true);

     const wrap = async (setter: (s: BlockState) => void, fn: () => Promise<Row[]>) => {
       setter({ loading: true, items: [] });
       try {
         const items = await fn();
         if (!alive) return;
         setter({ loading: false, items });
       } catch (e: any) {
         if (!alive) return;
         setter({ loading: false, items: [], error: e?.message || "Error" });
       }
     };

     await Promise.all([
       wrap(setLargeExes, () => loadBlock("/analysis/large-executables?limit=200")),
       wrap(setExesAppData, () => loadBlock("/analysis/exes-in-appdata?limit=200")),
       wrap(setScriptsTemp, () => loadBlock("/analysis/scripts-in-temp?limit=200")),
       wrap(setMultiHashes, () => loadBlock("/analysis/multi-use-hashes?limit=200")),
       wrap(setSysOutside, () => loadBlock("/analysis/system-process-outside-system32?limit=200")),
       wrap(setEntropySusp, () => loadBlock("/analysis/high-entropy-suspicious-paths?limit=200")),
       wrap(setIfeo, () => loadBlock("/analysis/ifeo-debuggers-suspicious?limit=200")),
       wrap(setRecentPe, () => loadBlock("/analysis/high-entropy-recent-pe?limit=200")),
     ]);

     if (!alive) return;
     setLoadingAll(false);
   }

   run();
   return () => {
     alive = false;
   };
 }, []);

 // ---- YARA select options from recentPe ----
 const recentPeByFilename = useMemo(() => {
   const map = new Map<string, Row>();
   for (const r of recentPe.items || []) {
     if (r?.filename) map.set(String(r.filename), r);
   }
   return map;
 }, [recentPe.items]);

 const yaraFiles = useMemo(() => {
   const names = Array.from(recentPeByFilename.keys());
   names.sort((a, b) => a.localeCompare(b));
   return names;
 }, [recentPeByFilename]);

 useEffect(() => {
   if (!yaraSelected && yaraFiles.length) setYaraSelected(yaraFiles[0]);
 }, [yaraFiles, yaraSelected]);

 async function generateYara() {
   setYaraMsg("");
   setYaraRule("");
   const row = recentPeByFilename.get(yaraSelected);
   if (!row) {
     setYaraMsg("Keine Datei ausgewählt.");
     return;
   }

   setYaraBusy(true);
   try {
     const res = await apiFetch("/analysis/yara-rule", {
       method: "POST",
       body: JSON.stringify({
         filename: row.filename,
         sha256: row.sha256,
         pe_sections: row.pe_sections,
         size: row.size,
       }),
     });

     if (!res.ok) {
       const msg = await res.text().catch(() => "");
       throw new Error(`${res.status} ${res.statusText} ${msg}`.trim());
     }

     const data = await res.json();
     const rule = data.rule as string | null;

     if (!rule) {
       setYaraMsg("⚠️ Keine Rule generiert – keine ungewöhnlichen PE Sections gefunden.");
     } else {
       setYaraRule(rule);
       setYaraMsg("✅ Rule generiert");
     }
   } catch (e: any) {
     setYaraMsg(e?.message || "Error");
   } finally {
     setYaraBusy(false);
   }
 }

 return (
   <div style={{ display: "grid", gap: 22 }}>
     <div>
       <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800 }}>
         📊 Deep Analysis Queries
       </h1>
       <div style={{ marginTop: 6, opacity: 0.75 }}>
         Alle Queries wie im Streamlit Dashboard – kompakt als Report-Ansicht.
       </div>
     </div>

     <AnalysisBlock
       title="💣 Large Executables >-50-MB"
       state={largeExes}
       columns={colsLargeExes}
       csvName="analysis_large_executables.csv"
     />

     <AnalysisBlock
       title="📁 Suspicious EXEs in AppData"
       state={exesAppData}
       columns={colsAppData}
       csvName="analysis_exes_in_appdata.csv"
     />

     <AnalysisBlock
       title="📂 Scripts in Temp/Download Directories"
       state={scriptsTemp}
       columns={colsScripts}
       csvName="analysis_scripts_in_temp.csv"
     />

     <AnalysisBlock
       title="🌀 Multi-use Hashes (Same SHA-256, multiple filenames)"
       state={multiHashes}
       columns={colsMultiHashes}
       csvName="analysis_multi_use_hashes.csv"
     />

     <AnalysisBlock
       title="⚙️ System Process Names Outside System32"
       state={sysOutside}
       columns={colsSysOutside}
       csvName="analysis_system_process_outside_system32.csv"
     />

     <AnalysisBlock
       title="🧠 High-Entropy Files in Suspicious Paths"
       state={entropySusp}
       columns={colsEntropySusp}
       csvName="analysis_high_entropy_suspicious_paths.csv"
     />

     <AnalysisBlock
       title="🧬 Suspicious IFEO Debuggers (Registry Scan)"
       state={ifeo}
       columns={colsIfeo}
       csvName="analysis_ifeo_debuggers.csv"
     />

     {/* High entropy recent PE + YARA (WIE VORHER, NICHT ENTFERNT) */}
     <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 16, display: "grid", gap: 12 }}>
       <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
         <h3 style={{ margin: 0 }}>🧬 High-Entropy Executables with Recent PE Metadata</h3>
         <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
           <Button
             onClick={() => downloadText("analysis_high_entropy_recent_pe.csv", toCsv(recentPe.items, colsRecentPe))}
             disabled={!recentPe.items.length}
           >
             ⬇️ Download CSV
           </Button>
         </div>
       </div>

       {recentPe.loading ? (
         <div style={{ opacity: 0.75 }}>Lade…</div>
       ) : recentPe.error ? (
         <div style={{ color: "crimson" }}>{recentPe.error}</div>
       ) : recentPe.items.length === 0 ? (
         <div style={{ opacity: 0.75 }}>No high-entropy executables with recent PE timestamps found.</div>
       ) : (
         <div style={{ overflowX: "auto" }}>
           <DataTable rows={recentPe.items} columns={colsRecentPe} />
         </div>
       )}

       <div style={{ borderTop: "1px solid #eee", paddingTop: 12, display: "grid", gap: 10 }}>
         <div style={{ fontWeight: 700 }}>🚀 Generate YARA rule</div>

         <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
           <label style={{ display: "grid", gap: 6 }}>
             <div style={{ fontSize: 13, opacity: 0.75 }}>Select a file</div>
             <select
               value={yaraSelected}
               onChange={(e) => setYaraSelected(e.target.value)}
               style={{ padding: "8px 10px", borderRadius: 8, border: "1px solid #ddd", minWidth: 280 }}
               disabled={!yaraFiles.length}
             >
               {yaraFiles.map((f) => (
                 <option key={f} value={f}>
                   {f}
                 </option>
               ))}
             </select>
           </label>

           <Button onClick={generateYara} disabled={!yaraSelected || yaraBusy || recentPe.loading}>
             {yaraBusy ? "Generating…" : "Generate"}
           </Button>

           {yaraRule && (
             <Button onClick={() => downloadText(`${yaraSelected}_rule.yar`, yaraRule, "text/plain")}>
               💾 Download .yar
             </Button>
           )}
         </div>

         {yaraMsg && <div style={{ opacity: 0.85 }}>{yaraMsg}</div>}

         {yaraRule && (
           <textarea
             value={yaraRule}
             readOnly
             style={{
               width: "100%",
               minHeight: 260,
               fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
               fontSize: 12.5,
               padding: 12,
               borderRadius: 10,
               border: "1px solid #ddd",
             }}
           />
         )}
       </div>
     </div>

     {!loadingAll && <div style={{ opacity: 0.6, fontSize: 12 }} />}
   </div>
 );
}

function AnalysisBlock({
 title,
 state,
 columns,
 csvName,
}: {
 title: string;
 state: BlockState;
 columns: { key: string; label: string }[];
 csvName: string;
}) {
 return (
   <div style={{ border: "1px solid #ddd", borderRadius: 12, padding: 16, display: "grid", gap: 12 }}>
     <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
       <h3 style={{ margin: 0 }}>{title}</h3>
       <Button onClick={() => downloadText(csvName, toCsv(state.items, columns))} disabled={!state.items.length}>
         ⬇️ Download CSV
       </Button>
     </div>

     {state.loading ? (
       <div style={{ opacity: 0.75 }}>Lade…</div>
     ) : state.error ? (
       <div style={{ color: "crimson" }}>{state.error}</div>
     ) : state.items.length === 0 ? (
       <div style={{ opacity: 0.75 }}>No entries found.</div>
     ) : (
       <div style={{ overflowX: "auto" }}>
         <DataTable rows={state.items} columns={columns} />
       </div>
     )}
   </div>
 );
}
