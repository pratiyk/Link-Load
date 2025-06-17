// src/App.js
import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from "react-router-dom";
import Layout from "./layout/Layout";
import LinkScanner from "./pages/LinkScanner";
import ThreatScanner from "./pages/ThreatScanner";
import VulnerabilityScanner from "./pages/VulnerabilityScanner"; // Import vulnerability scanner

function App() {
  return (
    <Router>
      <nav style={{ padding: "1rem", background: "#f0f0f0" }}>
        <Link to="/link-scanner" style={{ marginRight: 10 }}>Link Scanner</Link>
        <Link to="/threat-scanner" style={{ marginRight: 10 }}>Threat Scanner</Link>
        <Link to="/vulnerability-scanner">Vulnerability Scanner</Link>
      </nav>

      <Routes>
        <Route path="/" element={<Navigate to="/link-scanner" replace />} />

        <Route
          path="/link-scanner"
          element={
            <Layout>
              <LinkScanner />
            </Layout>
          }
        />

        <Route
          path="/threat-scanner"
          element={
            <Layout>
              <ThreatScanner />
            </Layout>
          }
        />

        <Route
          path="/vulnerability-scanner"
          element={
            <Layout>
              <VulnerabilityScanner />
            </Layout>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;
