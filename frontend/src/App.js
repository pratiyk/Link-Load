import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./layout/Layout";

import LinkScanner from "./pages/LinkScanner";
import ThreatScanner from "./pages/ThreatScanner";
import VulnerabilityScanner from "./pages/VulnerabilityScanner";
import Remediation from "./pages/Remediation";
import DarkWebMonitor from "./pages/DarkWebScanner";

// Import the global CSS
import "./index.css";

function App() {
  return (
    <Router>
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

        <Route
          path="/darkweb-scanner"
          element={
            <Layout>
              <DarkWebMonitor />
            </Layout>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;
