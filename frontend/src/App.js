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
import Verification from "./pages/Verification";
import ScanResults from "./pages/ScanResults";
import Profile from "./pages/Profile";
import MissionFile from "./pages/MissionFile";
import NotFound from "./pages/NotFound";

import "./styles/variables.css";
import "./App.css";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/scan/:scanId" element={<ScanResults />} />
        <Route path="/register" element={<Register />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/mission-file" element={<MissionFile />} />
        <Route path="/settings/verification" element={<Verification />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Router>
  );
}

export default App;