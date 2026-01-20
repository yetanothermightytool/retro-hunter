"use client";

import React from "react";

type Props = React.ButtonHTMLAttributes<HTMLButtonElement>;

export function Button({ children, ...props }: Props) {
 return (
   <button
     {...props}
     style={{
       padding: "10px 14px",
       borderRadius: 10,
       border: "none",
       background: "#2563eb",
       color: "#fff",
       fontWeight: 500,
       cursor: "pointer",
       boxShadow: "0 2px 6px rgba(0,0,0,0.2)",
     }}
     onMouseOver={(e) => (e.currentTarget.style.background = "#1d4ed8")}
     onMouseOut={(e) => (e.currentTarget.style.background = "#2563eb")}
   >
     {children}
   </button>
 );
}
