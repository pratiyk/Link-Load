import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./layout/Layout";

import LinkScanner from "./pages/LinkScanner";
import ThreatScanner from "./pages/ThreatScanner";
import VulnerabilityScanner from "./pages/VulnerabilityScanner";
import Remediation from "./pages/Remediation";
import DarkWebScanner from "./pages/DarkWebScanner";
import PhishingDetector from "./pages/PhishingDetector";
import AttackSurfaceMap from "./components/attack-surface/AttackSurfaceMap";
import ScanConfigurationPanel from "./components/attack-surface/ScanConfigurationPanel";
import ScansList from "./pages/AttackSurfaceScans";

import "./index.css";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Navigate to="/link-scanner" replace />} />

        <Route path="/link-scanner" element={<Layout><LinkScanner /></Layout>} />
        <Route path="/threat-scanner" element={<Layout><ThreatScanner /></Layout>} />
        <Route path="/vulnerability-scanner" element={<Layout><VulnerabilityScanner /></Layout>} />
        <Route path="/remediation" element={<Layout><Remediation /></Layout>} />
        <Route path="/darkweb-scanner" element={<Layout><DarkWebScanner /></Layout>} />
        <Route path="/phishing-detector" element={<Layout><PhishingDetector /></Layout>} />

        <Route path="/attack-surface" element={<Layout><ScansList /></Layout>} />
        <Route path="/attack-surface/new" element={<Layout><ScanConfigurationPanel /></Layout>} />
        <Route path="/attack-surface/:scanId" element={<Layout><AttackSurfaceMap /></Layout>} />
      </Routes>
    </Router>
  );
}

export default App;
