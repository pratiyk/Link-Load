import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import LinkScanner from "./pages/LinkScanner";

function App() {
  return (
    <Router>
      <Routes>
        {/* Add your other routes here */}
        <Route path="/link-scanner" element={<LinkScanner />} />
      </Routes>
    </Router>
  );
}

export default App;
