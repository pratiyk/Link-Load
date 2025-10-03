// src/components/SeverityBadge.js
import React from 'react';

export default function SeverityBadge({ severity }) {
  if (severity === null || severity === undefined) {
    return (
      <span className="badge badge-neutral">
        Unknown
      </span>
    );
  }

  let level = 'Low';
  let badgeClass = 'badge-success';

  if (severity >= 9.0) {
    level = 'Critical';
    badgeClass = 'badge-danger';
  } else if (severity >= 7.0) {
    level = 'High';
    badgeClass = 'badge-warning';
  } else if (severity >= 4.0) {
    level = 'Medium';
    badgeClass = 'badge-info';
  }

  return (
    <span className={`badge ${badgeClass}`}>
      {level} ({severity})
    </span>
  );
}