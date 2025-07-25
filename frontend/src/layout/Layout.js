// src/layout/Layout.js
import React from "react";
import TopNav from "./TopNav";

export default function Layout({ children }) {
  return (
    <div className="flex flex-col min-h-screen bg-[#F5F5F7] font-sans text-[#1C1C1E]">
      <TopNav />
      <main className="flex-1 p-6 max-w-6xl mx-auto">
        {children}
      </main>
    </div>
  );
}
