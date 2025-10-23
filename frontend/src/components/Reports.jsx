import React from 'react';

const Reports = ({ reports, onClose }) => {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal pixel-border" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="pixel-text">SCAN REPORTS</h3>
          <button className="close-btn pixel-text" onClick={onClose}>×</button>
        </div>
        <div className="modal-content">
          <div className="report-list">
            {reports.map((report, index) => (
              <div key={index} className="report-item pixel-border">
                <div className="report-header">
                  <span className="pixel-text">SCAN #{report.id}</span>
                  <span className="report-date pixel-text">{report.date}</span>
                </div>
                <div className="report-stats">
                  <div className="stat-row">
                    <span className="pixel-text">THREATS:</span>
                    <span className="value">{report.threats}</span>
                  </div>
                  <div className="stat-row">
                    <span className="pixel-text">SEVERITY:</span>
                    <span className={`value ${report.severity.toLowerCase()}`}>{report.severity}</span>
                  </div>
                </div>
                <button 
                  className="btn btn-secondary pixel-btn"
                  onClick={() => report.onViewDetails(report.id)}
                >
                  VIEW DETAILS
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Reports;