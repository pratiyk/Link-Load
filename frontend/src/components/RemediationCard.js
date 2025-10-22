import React from 'react';
import SeverityBadge from './SeverityBadge';

const RemediationCard = ({ mitigation }) => {
  const { step, priority, details } = mitigation;

  return (
    <div className="bg-white p-4 rounded-lg shadow border border-gray-200">
      <div className="flex justify-between items-center mb-2">
        <h3 className="text-lg font-medium">{step}</h3>
        <div className="priority-high">
          <SeverityBadge severity={priority} />
        </div>
      </div>
      {details && <p className="text-gray-600">{details}</p>}
    </div>
  );
};

export default RemediationCard;