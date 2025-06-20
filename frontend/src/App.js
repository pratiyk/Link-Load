// src/App.js
import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate, Link } from "react-router-dom";
import Layout from "./layout/Layout";

import LinkScanner from "./pages/LinkScanner";
import ThreatScanner from "./pages/ThreatScanner";
import VulnerabilityScanner from "./pages/VulnerabilityScanner";
import Remediation from "./pages/Remediation"; // ✅ New import

function App() {
  return (
    <Router>
      <nav style={{ padding: "1rem", background: "#f0f0f0" }}>
        <Link to="/link-scanner" style={{ marginRight: 10 }}>Link Scanner</Link>
        <Link to="/threat-scanner" style={{ marginRight: 10 }}>Threat Scanner</Link>
        <Link to="/vulnerability-scanner" style={{ marginRight: 10 }}>Vulnerability Scanner</Link>
        <Link to="/remediation">Remediation</Link> {/* ✅ Optional: show always or hide behind logic */}
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

        <Route
          path="/remediation"
          element={
            <Layout>
              <Remediation />
            </Layout>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;
