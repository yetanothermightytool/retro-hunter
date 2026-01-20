"use client";

import { useEffect, useMemo, useState } from "react";
import { apiFetch } from "../../lib/api";
import { DataTable } from "../../components/DataTable";
import { Button } from "../../components/Button";

type User = {
 id: number;
 email: string;
 role: string;
 created_at?: string;
};

function fmt(v: any) {
 if (!v) return "";
 try {
   return new Date(v).toLocaleString();
 } catch {
   return String(v);
 }
}

export default function UsersPage() {
 const [users, setUsers] = useState<User[]>([]);
 const [loading, setLoading] = useState(true);

 const [selected, setSelected] = useState<User | null>(null);

 // Create user state
 const [newEmail, setNewEmail] = useState("");
 const [newPassword, setNewPassword] = useState("");
 const [newRole, setNewRole] = useState("viewer");

 // Edit user state
 const [editRole, setEditRole] = useState("");
 const [editPassword, setEditPassword] = useState("");

 // Feedback
 const [message, setMessage] = useState<string | null>(null);
 const [error, setError] = useState<string | null>(null);

 async function loadUsers() {
   setLoading(true);
   setError(null);

   const res = await apiFetch("/admin/users");
   if (!res.ok) {
     setError("Could not load users!");
     setLoading(false);
     return;
   }

   const json = await res.json();
   setUsers(json.items ?? []);
   setLoading(false);
 }

 useEffect(() => {
   loadUsers();
 }, []);

 async function createUser() {
   setError(null);
   setMessage(null);

   if (!newEmail || !newPassword) {
     setError("Email and password are required.");
     return;
   }

   const res = await apiFetch("/admin/users", {
     method: "POST",
     body: JSON.stringify({
       email: newEmail,
       password: newPassword,
       role: newRole,
     }),
   });

   if (!res.ok) {
     setError("User could not be created!");
     return;
   }

   setNewEmail("");
   setNewPassword("");
   setNewRole("viewer");
   setMessage("User successfully created!");
   loadUsers();
 }

 async function updateUser() {
   if (!selected) return;

   setError(null);
   setMessage(null);

   const res = await apiFetch(`/admin/users/${selected.id}`, {
     method: "PUT",
     body: JSON.stringify({
       role: editRole || undefined,
       password: editPassword || undefined,
     }),
   });

   if (!res.ok) {
     setError("User could not be updated!");
     return;
   }

   setMessage("User updated.");
   setSelected(null);
   setEditPassword("");
   loadUsers();
 }

 async function deleteUser() {
   if (!selected) return;
   if (!confirm(`Delete user ${selected.email} ?`)) return;

   setError(null);
   setMessage(null);

   const res = await apiFetch(`/admin/users/${selected.id}`, {
     method: "DELETE",
   });

   if (!res.ok) {
     setError("User could not be deleted!");
     return;
   }

   setMessage("User deleted!");
   setSelected(null);
   loadUsers();
 }

 const userCols = useMemo(
   () => [
     { key: "id", label: "ID" },
     { key: "email", label: "Email" },
     { key: "role", label: "Role" },
     { key: "created_at", label: "Created" },
   ],
   []
 );

 const userView = useMemo(() => {
   return (users || []).map((u) => ({
     ...u,
     created_at: fmt(u.created_at),
   }));
 }, [users]);

 if (loading) return <div>Lade…</div>;

 return (
   <div style={{ display: "grid", gap: 24 }}>
     <h1 style={{ margin: 0, fontSize: 28, fontWeight: 800 }}>🕵🏾‍♀️  User Management</h1>
     {/* Feedback */}
     {message && <div style={{ color: "green" }}>{message}</div>}
     {error && <div style={{ color: "crimson" }}>{error}</div>}

     {/* Create User */}
     <div
       style={{
         padding: 16,
         border: "1px solid #ddd",
         borderRadius: 12,
         maxWidth: 420,
         display: "grid",
         gap: 10,
       }}
     >
       <h3 style={{ margin: 0 }}>Create User</h3>

       <input
         placeholder="Email"
         value={newEmail}
         onChange={(e) => setNewEmail(e.target.value)}
         style={{ padding: 8 }}
       />

       <input
         type="password"
         placeholder="Password"
         value={newPassword}
         onChange={(e) => setNewPassword(e.target.value)}
         style={{ padding: 8 }}
       />

       <select
         value={newRole}
         onChange={(e) => setNewRole(e.target.value)}
         style={{ padding: 8 }}
       >
         <option value="viewer">viewer</option>
         <option value="admin">admin</option>
       </select>

       <Button onClick={createUser}>Create</Button>
     </div>

     {/* Users Table */}
     <DataTable
       rows={userView}
       columns={userCols}
       selectedRowId={selected?.id}
       onRowClick={(row: User) => {
         setSelected(row);
         setEditRole(row.role);
         setEditPassword("");
       }}
     />

     {/* Edit User */}
     {selected && (
       <div
         style={{
           padding: 16,
           border: "1px solid #ddd",
           borderRadius: 12,
           maxWidth: 420,
           display: "grid",
           gap: 10,
         }}
       >
         <h3 style={{ margin: 0 }}>Edit User</h3>
         <div style={{ opacity: 0.7 }}>{selected.email}</div>

         <select
           value={editRole}
           onChange={(e) => setEditRole(e.target.value)}
           style={{ padding: 8 }}
         >
           <option value="viewer">viewer</option>
           <option value="admin">admin</option>
         </select>

         <input
           type="password"
           placeholder="New password (optional)"
           value={editPassword}
           onChange={(e) => setEditPassword(e.target.value)}
           style={{ padding: 8 }}
         />

         <div style={{ display: "flex", gap: 10 }}>
           <Button onClick={updateUser}>Save</Button>
           <Button onClick={deleteUser} style={{ background: "#dc2626" }}>
             Delete
           </Button>
           <button
             onClick={() => setSelected(null)}
             style={{
               background: "none",
               border: "none",
               cursor: "pointer",
             }}
           >
             Cancel
           </button>
         </div>
       </div>
     )}
   </div>
 );
}
