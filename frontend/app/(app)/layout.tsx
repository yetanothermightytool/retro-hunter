"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { apiFetch } from "../lib/api";
import { Button } from "../components/Button";
import { Footer } from "../components/Footer";

type Theme = "light" | "dark";

export default function AppLayout({ children }: { children: React.ReactNode }) {
 const [user, setUser] = useState<{ email: string; role: string } | null>(null);
 const [theme, setTheme] = useState<Theme>("light");

 const router = useRouter();
 const pathname = usePathname();

 useEffect(() => {
   // auth
   apiFetch("/auth/me").then(async (res) => {
     if (res.status === 401) {
       router.push("/login");
       return;
     }
     setUser(await res.json());
   });
 }, [router]);

 useEffect(() => {
   // theme init
   const saved = (localStorage.getItem("theme") as Theme | null) ?? "light";
   applyTheme(saved);
   setTheme(saved);
 }, []);

 function applyTheme(t: Theme) {
   document.documentElement.dataset.theme = t;
   localStorage.setItem("theme", t);
 }

 function toggleTheme() {
   const next: Theme = theme === "light" ? "dark" : "light";
   setTheme(next);
   applyTheme(next);
 }

 async function doLogout() {
   await apiFetch("/auth/logout", { method: "POST" });
   router.push("/login");
 }

 if (!user) return <div style={{ padding: 24 }}>Lade…</div>;

 const Tab = ({ href, label }: { href: string; label: string }) => (
   <Link
     href={href}
     style={{
       padding: "8px 12px",
       borderRadius: 8,
       textDecoration: "none",
       border: "1px solid var(--border)",
       background: pathname === href ? "var(--tabActive)" : "transparent",
       color: "var(--text)",
     }}
   >
     {label}
   </Link>
 );

 return (
   <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column", background: "var(--bg)", color: "var(--text)" }}>
     {/* Theme variables (nur für App-Bereich) */}
     <style jsx global>{`
       :root[data-theme="light"] {
         --bg: #ffffff;
         --text: #111827;
         --muted: #6b7280;
         --border: #e5e7eb;
         --tabActive: #eeeeee;
       }
       :root[data-theme="dark"] {
         --bg: #0b1220;
         --text: #e5e7eb;
         --muted: #9ca3af;
         --border: #243047;
         --tabActive: #172033;
       }
     `}</style>

     <div style={{ padding: 24, display: "grid", gap: 16 }}>
       <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
         <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
           <Tab href="/" label="Overview" />
           <Tab href="/scans" label="Scans" />
           <Tab href="/analysis" label="Deep Analysis" />
           <Tab href="/events" label="Events" />
           {user.role === "admin" && <Tab href="/users" label="User Mgmt" />}
         </div>

         <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
           <div style={{ opacity: 0.85, color: "var(--text)" }}>
             {user.email} ({user.role})
           </div>

           <button
             onClick={toggleTheme}
             style={{
               padding: "8px 12px",
               borderRadius: 10,
               border: "1px solid var(--border)",
               background: "transparent",
               color: "var(--text)",
               cursor: "pointer",
             }}
           >
             {theme === "light" ? "Dark" : "Light"}
           </button>

           <Button onClick={doLogout}>Logout</Button>
         </div>
       </div>

       <div>{children}</div>
     </div>

     <div style={{ marginTop: "auto" }}>
       <Footer />
     </div>
   </div>
 );
}
