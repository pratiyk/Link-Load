import React from "react";
import { Link, useLocation } from "react-router-dom";
import {
  ScanSearch,
  ShieldCheck,
  Bug,
  Wrench,
} from "lucide-react";

export default function Layout({ children }) {
  const location = useLocation();

  const navItems = [
    { name: "Link Scanner", path: "/link-scanner", icon: ScanSearch },
    { name: "Threat Scanner", path: "/threat-scanner", icon: ShieldCheck },
    { name: "Vulnerability Scanner", path: "/vulnerability-scanner", icon: Bug },
    { name: "Remediation", path: "/remediation", icon: Wrench },
  ];

  const renderNav = () => (
    <ul className="space-y-2 mt-4">
      {navItems.map((item) => {
        const isActive = location.pathname === item.path;
        return (
          <li key={item.path}>
            <Link
              to={item.path}
              className={`flex items-center gap-3 px-4 py-2 rounded-lg transition-colors font-medium ${
                isActive
                  ? "bg-blue-600 text-white shadow"
                  : "text-gray-700 hover:bg-blue-100"
              }`}
            >
              <item.icon className="w-5 h-5" />
              {item.name}
            </Link>
          </li>
        );
      })}
    </ul>
  );

  return (
    <div className="flex min-h-screen bg-gray-50">
      {/* Sidebar */}
      <aside className="w-full md:w-64 bg-white border-r px-6 py-6 md:py-8 shadow-sm z-10">
        <h1 className="text-2xl font-extrabold text-blue-700 mb-6">Link&Load</h1>
        {renderNav()}
      </aside>

      {/* Main Content */}
      <main className="flex-1 p-6 md:p-8 overflow-y-auto">{children}</main>
    </div>
  );
}
