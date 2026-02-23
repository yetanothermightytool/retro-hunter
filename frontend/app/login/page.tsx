"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { apiFetch } from "../lib/api";
import { Button } from "../components/Button";
import { Footer } from "../components/Footer-Login";

export default function LoginPage() {
 const [email, setEmail] = useState("");
 const [password, setPassword] = useState("");
 const [error, setError] = useState("");
 const [loading, setLoading] = useState(false);
 const router = useRouter();

 async function onSubmit(e: React.FormEvent) {
   e.preventDefault();
   setError("");
   setLoading(true);

   try {
     const res = await apiFetch("/auth/login", {
       method: "POST",
       body: JSON.stringify({ email, password }),
     });

     if (!res.ok) {
       const data = await res.json().catch(() => null);
       setError(data?.message ?? "Login failed!");
       return;
     }

     router.push("/");
   } catch {
     setError("Connection error. Please try again.");
   } finally {
     setLoading(false);
   }
 }

 return (
   <div
     style={{
       minHeight: "100vh",
       backgroundImage: "url(/login-bg.png)",
       backgroundRepeat: "no-repeat",
       backgroundPosition: "center",
       backgroundSize: "contain",
       backgroundColor: "#0f172a",
       display: "grid",
       placeItems: "center",
       padding: 24,
     }}
   >
     <div
       style={{
         width: "100%",
         maxWidth: 360,
         padding: 24,
         borderRadius: 14,
         background: "rgba(255,255,255,0.75)",
         backdropFilter: "blur(8px)",
         border: "1px solid rgba(255,255,255,0.25)",
         boxShadow: "0 10px 30px rgba(0,0,0,0.25)",
       }}
     >
       <form onSubmit={onSubmit} style={{ display: "grid", gap: 10 }}>
         <h2 style={{ color: "black", margin: 0 }}>Retro Hunter Login</h2>

         <input
           name="email"
           autoComplete="username"
           placeholder="Email"
           value={email}
           onChange={(e) => setEmail(e.target.value)}
           disabled={loading}
           required
           style={{
             color: "black", padding: 10, borderRadius: 10,
             border: "1px solid #ddd", opacity: loading ? 0.6 : 1,
           }}
         />

         <input
           name="password"
           type="password"
           autoComplete="current-password"
           placeholder="Password"
           value={password}
           onChange={(e) => setPassword(e.target.value)}
           disabled={loading}
           required
           style={{
             color: "black", padding: 10, borderRadius: 10,
             border: "1px solid #ddd", opacity: loading ? 0.6 : 1,
           }}
         />

         <Button type="submit" disabled={loading}>
           {loading ? "Signing in…" : "Login"}
         </Button>

         <Footer />

         {error && (
           <p role="alert" style={{ color: "crimson", margin: 0 }}>
             {error}
           </p>
         )}
       </form>
     </div>
   </div>
 );
}
