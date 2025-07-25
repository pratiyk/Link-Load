// src/layout/TopNav.js
import React from "react";
import { NavLink } from "react-router-dom";
import {
  ScanSearch,
  ShieldCheck,
  Bug,
  Wrench,
  Eye,
  ShieldQuestion,
  Map
} from "lucide-react";

const NAV_BG = "#FFFFFF";
const NAV_BORDER = "#D1D1D6";
const TEXT = "#1C1C1E";
const ACCENT = "#478504ff";

export default function TopNav() {
  const navItems = [
    { name: "Link Scanner", path: "/link-scanner", icon: ScanSearch },
    { name: "Threat Scanner", path: "/threat-scanner", icon: ShieldCheck },
    { name: "Vulnerability", path: "/vulnerability-scanner", icon: Bug },
    { name: "Remediation", path: "/remediation", icon: Wrench },
    { name: "Dark Web", path: "/darkweb-scanner", icon: Eye },
    { name: "Phishing", path: "/phishing-detector", icon: ShieldQuestion },
    { name: "Attack Surface", path: "/attack-surface", icon: Map },
  ];

  return (
    <header
      style={{ background: NAV_BG, borderBottom: `1px solid ${NAV_BORDER}` }}
      className="sticky top-0 z-50"
    >
      <div className="max-w-6xl mx-auto flex items-center justify-between px-4 py-2">
        {/* Logo */}
        <div className="flex items-center space-x-2">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center text-white font-bold"
            style={{ background: ACCENT }}
          >
            
          </div>
          <span className="text-lg font-medium" style={{ color: TEXT }}>
            <h1>Link&Load</h1>
          </span>
        </div>

        {/* Nav */}
        <nav className="hidden md:flex space-x-6">
          {navItems.map(({ name, path, icon: Icon }) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) =>
                `flex items-center space-x-1 text-sm font-medium transition-colors ${
                  isActive
                    ? "border-b-2 pb-1"
                    : "opacity-70 hover:opacity-100"
                }`
              }
              style={({ isActive }) => ({
                color: isActive ? ACCENT : TEXT,
                borderColor: isActive ? ACCENT : "transparent"
              })}
            >
              <Icon className="w-5 h-5" />
              <span>{name}</span>
            </NavLink>
          ))}
        </nav>

        {/* Mobile menu placeholder */}
        <button className="md:hidden p-2">
          <svg
            className="w-6 h-6"
            fill="none"
            stroke={TEXT}
            viewBox="0 0 24 24"
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
    </header>
  );
}
