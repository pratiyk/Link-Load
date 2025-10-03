// src/layout/Layout.js
import React from "react";
import TopNav from "./TopNav";

export default function Layout({ children }) {
  return (
    <div style={{ 
      display: 'flex', 
      flexDirection: 'column', 
      minHeight: '100vh',
      backgroundColor: 'var(--color-bg-primary)'
    }}>
      <TopNav />
      <main style={{
        flex: 1,
        padding: 'var(--spacing-6)',
        maxWidth: '1200px',
        margin: '0 auto',
        width: '100%'
      }}>
        {children}
      </main>
    </div>
  );
}
