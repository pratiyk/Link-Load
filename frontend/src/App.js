import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./layout/Layout";
import { AuthProvider } from "./context/AuthContext";

import LinkScanner from "./pages/LinkScanner";
import ThreatScanner from "./pages/ThreatScanner";
import VulnerabilityScanner from "./pages/VulnerabilityScanner";
import Remediation from "./pages/Remediation";
import PhishingDetector from "./pages/PhishingDetector";
import AttackSurfaceMap from "./components/attack-surface/AttackSurfaceMap";
import ScanConfigurationPanel from "./components/attack-surface/ScanConfigurationPanel";
import ScansList from "./pages/AttackSurfaceScans";
import OWASPScanner from "./pages/OWASPScanner";
import Login from "./pages/Login";
import Register from "./pages/Register";
import Profile from "./pages/Profile";
import NotFound from "./pages/NotFound";

import "./App.css";

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Navigate to="/link-scanner" replace />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/profile" element={<Layout><Profile /></Layout>} />
          
          <Route path="/link-scanner" element={<Layout><LinkScanner /></Layout>} />
          <Route path="/threat-scanner" element={<Layout><ThreatScanner /></Layout>} />
          <Route path="/vulnerability-scanner" element={<Layout><VulnerabilityScanner /></Layout>} />
          <Route path="/remediation" element={<Layout><Remediation /></Layout>} />
          <Route path="/phishing-detector" element={<Layout><PhishingDetector /></Layout>} />
          <Route path="/attack-surface" element={<Layout><ScansList /></Layout>} />
          <Route path="/attack-surface/new" element={<Layout><ScanConfigurationPanel /></Layout>} />
          <Route path="/attack-surface/:scanId" element={<Layout><AttackSurfaceMap /></Layout>} />
          <Route path="/owasp-scanner" element={<Layout><OWASPScanner /></Layout>} />
          
          <Route path="*" element={<Layout><NotFound /></Layout>} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;