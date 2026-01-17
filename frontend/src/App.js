// Debug: Log test env variable
if (typeof window !== 'undefined') {
  // eslint-disable-next-line no-console
  console.log('[DEBUG] TEST ENV VARIABLE:', process.env.REACT_APP_TEST_VARIABLE);
}
import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import Verification from "./pages/Verification";
import ScanResults from "./pages/ScanResults";
import Profile from "./pages/Profile";
import MissionFile from "./pages/MissionFile";
import NotFound from "./pages/NotFound";
import ApiSecurity from "./pages/ApiSecurity";
import SourceCodeSecurity from "./pages/SourceCodeSecurity";
import CloudSecurityPosture from "./pages/CloudSecurityPosture";

import "./styles/variables.css";
import "./App.css";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/scan/:scanId" element={<ScanResults />} />
        <Route path="/register" element={<Register />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/mission-file" element={<MissionFile />} />
        <Route path="/settings/verification" element={<Verification />} />
        <Route path="/capabilities/api-security" element={<ApiSecurity />} />
        <Route path="/capabilities/source-code-security" element={<SourceCodeSecurity />} />
        <Route path="/capabilities/cloud-security-posture" element={<CloudSecurityPosture />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Router>
  );
}

export default App;