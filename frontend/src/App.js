// src/App.js
import React from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./layout/Layout";
import LinkScanner from "./pages/LinkScanner";
import ThreatScanner from "./pages/ThreatScanner";

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
      </Routes>
    </Router>
  );
}

export default App;
