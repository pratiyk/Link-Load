// src/components/SeverityBadge.js
import React from 'react';

export default function SeverityBadge({ severity }) {
  if (severity === null || severity === undefined) {
    return (
      <span className="px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
        Unknown
      </span>
    );
  }

  let level = 'Low';
  let bgColor = 'bg-green-100';
  let textColor = 'text-green-800';
  let borderColor = 'border-green-300';

  if (severity >= 9.0) {
    level = 'Critical';
    bgColor = 'bg-red-100';
    textColor = 'text-red-800';
    borderColor = 'border-red-300';
  } else if (severity >= 7.0) {
    level = 'High';
    bgColor = 'bg-orange-100';
    textColor = 'text-orange-800';
    borderColor = 'border-orange-300';
  } else if (severity >= 4.0) {
    level = 'Medium';
    bgColor = 'bg-yellow-100';
    textColor = 'text-yellow-800';
    borderColor = 'border-yellow-300';
  }

  return (
    <span className={`px-2.5 py-1 rounded-full text-xs font-medium border ${bgColor} ${textColor} ${borderColor}`}>
      {level} ({severity})
    </span>
  );
}