"use client";

export function Footer() {
 const now = new Date().toISOString().slice(0, 19).replace("T", " ");

 return (
   <div
     style={{
       marginTop: 40,
       fontSize: 12,
       color: "#6b7280",
       textAlign: "center",
       lineHeight: 1.6,
     }}
   >
     <div>
       🕵🏾‍♀️ Retro Hunter – powered by Veeam Data Integration API ({now}) – Version 3.0
       PostgreSQL
     </div>
     <div>
       🤖 Some logic and optimizations were assisted using AI tools.
     </div>
   </div>
 );
}
