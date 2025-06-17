// src/layout/Layout.js
import React from "react";
import { Link, useLocation } from "react-router-dom";

export default function Layout({ children }) {
  const location = useLocation();

  const navItems = [
    { name: "Link Scanner", path: "/link-scanner" },
    { name: "Threat Scanner", path: "/threat-scanner" },
    { name: "Vulnerability Scanner", path: "/vulnerability-scanner" }, // Added this
  ];

  return (
    <div className="flex min-h-screen bg-gray-100">
      {/* Sidebar */}
      <div className="w-64 bg-white border-r p-4">
        <h1 className="text-2xl font-bold mb-6">Link&Load</h1>
        <ul className="space-y-3">
          {navItems.map((item) => (
            <li key={item.path}>
              <Link
                to={item.path}
                className={`block px-4 py-2 rounded ${
                  location.pathname === item.path
                    ? "bg-blue-500 text-white"
                    : "hover:bg-gray-200 text-gray-800"
                }`}
              >
                {item.name}
              </Link>
            </li>
          ))}
        </ul>
      </div>

      {/* Main content */}
      <div className="flex-1 p-6">{children}</div>
    </div>
  );
}
