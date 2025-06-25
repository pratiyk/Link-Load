// src/layout/TopNav.js
import React from "react";
import { NavLink } from "react-router-dom";
import {
  ScanSearch,
  ShieldCheck,
  Bug,
  Wrench,
  Eye, // 👈 New icon for Dark Web Monitor
} from "lucide-react";

export default function TopNav() {
  const navItems = [
    { name: "Link Scanner", path: "/link-scanner", icon: ScanSearch },
    { name: "Threat Scanner", path: "/threat-scanner", icon: ShieldCheck },
    { name: "Vulnerability Scanner", path: "/vulnerability-scanner", icon: Bug },
    { name: "Remediation", path: "/remediation", icon: Wrench },
    { name: "Dark Web Scanner", path: "/darkweb-scanner", icon: Eye }, // 👈 Add this line
  ];

  return (
    <header className="bg-white border-b border-gray-200 px-6 py-3">
      <div className="flex items-center justify-between max-w-7xl mx-auto">
        <div className="flex items-center">
          <div className="bg-gradient-to-r from-purple-600 to-green-500 w-10 h-10 rounded-lg flex items-center justify-center text-white font-bold text-xl mr-4">
            L&L
          </div>
          <h1 className="text-xl font-bold text-gray-900">Link&Load</h1>
        </div>

        <nav className="hidden md:flex space-x-1">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center px-4 py-2 rounded-lg transition-colors ${
                  isActive
                    ? "bg-gray-100 text-purple-700 font-medium"
                    : "text-gray-700 hover:bg-gray-50"
                }`
              }
            >
              <item.icon className="w-5 h-5 mr-2" />
              {item.name}
            </NavLink>
          ))}
        </nav>

        <div className="md:hidden">
          {/* Mobile menu button (optional enhancement) */}
          <button className="text-gray-500">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              className="h-6 w-6"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 6h16M4 12h16M4 18h16"
              />
            </svg>
          </button>
        </div>
      </div>
    </header>
  );
}
