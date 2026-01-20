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
 const router = useRouter();

 async function onSubmit(e: React.FormEvent) {
   e.preventDefault();
   setError("");

   const res = await apiFetch("/auth/login", {
     method: "POST",
     body: JSON.stringify({ email, password }),
   });

   if (!res.ok) {
     setError("Login failed!");
     return;
   }

   router.push("/");
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
         <h2 style={{ margin: 0 }}>Retro Hunter Login</h2>

         <input
           name="email"
           autoComplete="username"
           placeholder="Email"
           value={email}
           onChange={(e) => setEmail(e.target.value)}
           style={{ padding: 10, borderRadius: 10, border: "1px solid #ddd" }}
         />

         <input
           name="password"
           type="password"
           autoComplete="current-password"
           placeholder="Password"
           value={password}
           onChange={(e) => setPassword(e.target.value)}
           style={{ padding: 10, borderRadius: 10, border: "1px solid #ddd" }}
         />

         <Button type="submit">
           Login
         </Button>
	 
         <Footer />

         {error && <p style={{ color: "crimson", margin: 0 }}>{error}</p>}
       </form>
     </div>
   </div>
 );
}
