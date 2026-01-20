"use client";

import { useEffect, useRef, useState } from "react";

type Column = {
 key: string;
 label: string;
};

type Props = {
 rows: any[];
 columns?: Column[];
 onRowClick?: (row: any) => void;
 selectedRowId?: number;
};

export function DataTable({
 rows,
 columns,
 onRowClick,
 selectedRowId,
}: Props) {
 const topRef = useRef<HTMLDivElement | null>(null);
 const bottomRef = useRef<HTMLDivElement | null>(null);
 const tableRef = useRef<HTMLTableElement | null>(null);
 const [tableWidth, setTableWidth] = useState(0);

 useEffect(() => {
   setTableWidth(tableRef.current?.scrollWidth ?? 0);
 }, [rows, columns]);

 useEffect(() => {
   const top = topRef.current;
   const bottom = bottomRef.current;
   if (!top || !bottom) return;

   const syncTop = () => (bottom.scrollLeft = top.scrollLeft);
   const syncBottom = () => (top.scrollLeft = bottom.scrollLeft);

   top.addEventListener("scroll", syncTop);
   bottom.addEventListener("scroll", syncBottom);

   return () => {
     top.removeEventListener("scroll", syncTop);
     bottom.removeEventListener("scroll", syncBottom);
   };
 }, [tableWidth]);

 if (!rows || rows.length === 0) {
   return <div style={{ opacity: 0.7 }}>No data available.</div>;
 }

 const cols: Column[] =
   columns ??
   Object.keys(rows[0]).map((k) => ({
     key: k,
     label: k,
   }));

 const highlightEnabled =
   selectedRowId !== undefined && selectedRowId !== null;

 return (
   <div style={{ display: "grid", gap: 6 }}>
     {/* Top scrollbar */}
     <div
       ref={topRef}
       style={{
         overflowX: "auto",
         overflowY: "hidden",
         height: 12,
       }}
     >
       <div style={{ width: tableWidth, height: 1 }} />
     </div>

     {/* Table */}
     <div ref={bottomRef} style={{ overflowX: "auto" }}>
       <table
         ref={tableRef}
         style={{
           borderCollapse: "collapse",
           width: "max-content",
           background: "transparent",
         }}
       >
         <thead>
           <tr>
             {cols.map((c) => (
               <th
                 key={c.key}
                 style={{
                   padding: "8px 10px",
                   textAlign: "left",
                   fontWeight: 600,
                   whiteSpace: "nowrap",
                   borderBottom: "1px solid rgba(128,128,128,0.3)",
                 }}
               >
                 {c.label}
               </th>
             ))}
           </tr>
         </thead>

         <tbody>
           {rows.map((row, idx) => {
             const isSelected =
               highlightEnabled &&
               row?.id !== undefined &&
               row.id === selectedRowId;

             return (
               <tr
                 key={idx}
                 onClick={() => onRowClick?.(row)}
                 style={{
                   cursor: onRowClick ? "pointer" : "default",
                   background: isSelected
                     ? "rgba(100,150,255,0.15)"
                     : "transparent",
                 }}
               >
                 {cols.map((c) => (
                   <td
                     key={c.key}
                     style={{
                       padding: "8px 10px",
                       whiteSpace: "nowrap",
                       borderBottom: "1px solid rgba(128,128,128,0.15)",
                     }}
                   >
                     {String(row?.[c.key] ?? "")}
                   </td>
                 ))}
               </tr>
             );
           })}
         </tbody>
       </table>
     </div>
   </div>
 );
}
