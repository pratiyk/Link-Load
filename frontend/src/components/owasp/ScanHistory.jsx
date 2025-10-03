import React from "react";
import { Card, Table, Badge } from "react-bootstrap";
import { Clock, CheckCircle, XCircle, AlertCircle } from "react-feather";
import { format } from "date-fns";

const ScanHistory = ({ scans, onViewScan }) => {
  const getStatusBadge = (status) => {
    switch (status) {
      case 'completed': 
        return <Badge bg="success" className="d-flex align-items-center">
          <CheckCircle size={14} className="me-1" /> Completed
        </Badge>;
      case 'in-progress': 
        return <Badge bg="primary" className="d-flex align-items-center">
          <Clock size={14} className="me-1" /> In Progress
        </Badge>;
      case 'failed': 
        return <Badge bg="danger" className="d-flex align-items-center">
          <XCircle size={14} className="me-1" /> Failed
        </Badge>;
      case 'cancelled': 
        return <Badge bg="warning" className="d-flex align-items-center">
          <AlertCircle size={14} className="me-1" /> Cancelled
        </Badge>;
      default: 
        return <Badge bg="secondary">{status}</Badge>;
    }
  };

  const getSeveritySummary = (summary) => {
    if (!summary) return null;
    
    return (
      <div className="d-flex">
        {summary.critical_count > 0 && (
          <span className="me-2 text-danger fw-bold">
            {summary.critical_count} Critical
          </span>
        )}
        {summary.high_count > 0 && (
          <span className="me-2 text-warning fw-bold">
            {summary.high_count} High
          </span>
        )}
        {summary.medium_count > 0 && (
          <span className="me-2 text-info">
            {summary.medium_count} Medium
          </span>
        )}
        {summary.low_count > 0 && (
          <span className="me-2 text-muted">
            {summary.low_count} Low
          </span>
        )}
        {!summary.critical_count && !summary.high_count && 
         !summary.medium_count && !summary.low_count && (
          <span className="text-success">No vulnerabilities found</span>
        )}
      </div>
    );
  };

  return (
    <Card>
      <Card.Body>
        <div className="d-flex justify-content-between align-items-center mb-4">
          <Card.Title>Scan History</Card.Title>
          <div>
            {scans.length} scans
          </div>
        </div>
        
        {scans.length === 0 ? (
          <div className="text-center py-5">
            <h4>No scans yet</h4>
            <p className="text-muted">Start your first security scan to see results here</p>
          </div>
        ) : (
          <div className="table-responsive">
            <Table hover>
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Started</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Results</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.scan_id}>
                    <td>
                      <div className="text-truncate" style={{ maxWidth: "200px" }}>
                        {scan.target_url}
                      </div>
                    </td>
                    <td>
                      {format(new Date(scan.started_at), 'MMM dd, yyyy HH:mm')}
                    </td>
                    <td>
                      {getStatusBadge(scan.status)}
                    </td>
                    <td>
                      {scan.duration ? `${Math.round(scan.duration / 60)}m` : '-'}
                    </td>
                    <td>
                      {scan.summary ? getSeveritySummary(scan.summary) : '-'}
                    </td>
                    <td>
                      <button
                        className="btn btn-sm btn-outline-primary"
                        onClick={() => onViewScan(scan)}
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
        )}
      </Card.Body>
    </Card>
  );
};

export default ScanHistory;