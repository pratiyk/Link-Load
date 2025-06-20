// src/layout/Layout.js
import React, { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  ScanSearch,
  ShieldCheck,
  Bug,
  Wrench,
  Menu,
  X,
} from "lucide-react";

export default function Layout({ children }) {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { name: "Link Scanner", path: "/link-scanner", icon: ScanSearch },
    { name: "Threat Scanner", path: "/threat-scanner", icon: ShieldCheck },
    { name: "Vulnerability Scanner", path: "/vulnerability-scanner", icon: Bug },
    { name: "Remediation", path: "/remediation", icon: Wrench },
  ];

  const renderNav = () => (
    <ul className="space-y-3 mt-6">
      {navItems.map((item) => (
        <li key={item.path}>
          <Link
            to={item.path}
            className={`flex items-center gap-3 px-4 py-2 rounded ${
              location.pathname === item.path
                ? "bg-blue-600 text-white"
                : "text-gray-800 hover:bg-gray-200"
            }`}
            onClick={() => setMobileMenuOpen(false)}
          >
            <item.icon className="w-5 h-5" />
            {item.name}
          </Link>
        </li>
      ))}
    </ul>
  );

  return (
    <div className="flex flex-col md:flex-row min-h-screen bg-gray-100">
      {/* Mobile Navbar */}
      <div className="md:hidden bg-white shadow p-4 flex justify-between items-center">
        <h1 className="text-xl font-bold">Link&Load</h1>
        <button onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
          {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Sidebar */}
      <aside
        className={`${
          mobileMenuOpen ? "block" : "hidden"
        } md:block w-full md:w-64 bg-white border-r p-4 md:p-6`}
      >
        <h1 className="hidden md:block text-2xl font-bold mb-4">Link&Load</h1>
        {renderNav()}
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-6 overflow-auto">{children}</main>
    </div>
  );
}
