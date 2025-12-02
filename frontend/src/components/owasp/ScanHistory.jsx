import React, { useState } from "react";
import { Card, Table, Badge, Button, Modal, Spinner } from "react-bootstrap";
import { Clock, CheckCircle, XCircle, AlertCircle, Trash2 } from "react-feather";
import { format } from "date-fns";

const ScanHistory = ({ scans, onViewScan, onDeleteScan, onRefresh }) => {
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [scanToDelete, setScanToDelete] = useState(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [selectedScans, setSelectedScans] = useState([]);
  const [showBulkDeleteModal, setShowBulkDeleteModal] = useState(false);

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

  const handleDeleteClick = (scan) => {
    setScanToDelete(scan);
    setShowDeleteModal(true);
  };

  const handleConfirmDelete = async () => {
    if (!scanToDelete) return;

    setIsDeleting(true);
    try {
      if (onDeleteScan) {
        await onDeleteScan(scanToDelete.scan_id);
      }
      setShowDeleteModal(false);
      setScanToDelete(null);
      if (onRefresh) {
        onRefresh();
      }
    } catch (error) {
      console.error("Failed to delete scan:", error);
    } finally {
      setIsDeleting(false);
    }
  };

  const handleSelectScan = (scanId) => {
    setSelectedScans(prev =>
      prev.includes(scanId)
        ? prev.filter(id => id !== scanId)
        : [...prev, scanId]
    );
  };

  const handleSelectAll = () => {
    if (selectedScans.length === scans.length) {
      setSelectedScans([]);
    } else {
      setSelectedScans(scans.map(s => s.scan_id));
    }
  };

  const handleBulkDelete = async () => {
    setIsDeleting(true);
    try {
      if (onDeleteScan) {
        for (const scanId of selectedScans) {
          await onDeleteScan(scanId);
        }
      }
      setShowBulkDeleteModal(false);
      setSelectedScans([]);
      if (onRefresh) {
        onRefresh();
      }
    } catch (error) {
      console.error("Failed to delete scans:", error);
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <>
      <Card>
        <Card.Body>
          <div className="d-flex justify-content-between align-items-center mb-4">
            <Card.Title>Scan History</Card.Title>
            <div className="d-flex align-items-center gap-2">
              {selectedScans.length > 0 && (
                <Button
                  variant="outline-danger"
                  size="sm"
                  onClick={() => setShowBulkDeleteModal(true)}
                >
                  <Trash2 size={14} className="me-1" />
                  Delete Selected ({selectedScans.length})
                </Button>
              )}
              <span className="text-muted">{scans.length} scans</span>
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
                    <th style={{ width: "40px" }}>
                      <input
                        type="checkbox"
                        checked={selectedScans.length === scans.length && scans.length > 0}
                        onChange={handleSelectAll}
                        className="form-check-input"
                      />
                    </th>
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
                        <input
                          type="checkbox"
                          checked={selectedScans.includes(scan.scan_id)}
                          onChange={() => handleSelectScan(scan.scan_id)}
                          className="form-check-input"
                        />
                      </td>
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
                        <div className="d-flex gap-1">
                          <Button
                            variant="outline-primary"
                            size="sm"
                            onClick={() => onViewScan(scan)}
                          >
                            View
                          </Button>
                          <Button
                            variant="outline-danger"
                            size="sm"
                            onClick={() => handleDeleteClick(scan)}
                            title="Delete scan permanently"
                          >
                            <Trash2 size={14} />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </div>
          )}
        </Card.Body>
      </Card>

      {/* Single Delete Confirmation Modal */}
      <Modal show={showDeleteModal} onHide={() => setShowDeleteModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Delete Scan</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>Are you sure you want to permanently delete this scan?</p>
          {scanToDelete && (
            <div className="bg-light p-3 rounded">
              <strong>Target:</strong> {scanToDelete.target_url}<br />
              <strong>Date:</strong> {format(new Date(scanToDelete.started_at), 'MMM dd, yyyy HH:mm')}
            </div>
          )}
          <p className="text-danger mt-3 mb-0">
            <strong>Warning:</strong> This action cannot be undone. All scan data and vulnerabilities will be permanently deleted.
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowDeleteModal(false)} disabled={isDeleting}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleConfirmDelete} disabled={isDeleting}>
            {isDeleting ? (
              <>
                <Spinner size="sm" className="me-2" />
                Deleting...
              </>
            ) : (
              <>
                <Trash2 size={14} className="me-1" />
                Delete Permanently
              </>
            )}
          </Button>
        </Modal.Footer>
      </Modal>

      {/* Bulk Delete Confirmation Modal */}
      <Modal show={showBulkDeleteModal} onHide={() => setShowBulkDeleteModal(false)} centered>
        <Modal.Header closeButton>
          <Modal.Title>Delete Multiple Scans</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          <p>Are you sure you want to permanently delete <strong>{selectedScans.length}</strong> scans?</p>
          <p className="text-danger mb-0">
            <strong>Warning:</strong> This action cannot be undone. All scan data and vulnerabilities will be permanently deleted.
          </p>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowBulkDeleteModal(false)} disabled={isDeleting}>
            Cancel
          </Button>
          <Button variant="danger" onClick={handleBulkDelete} disabled={isDeleting}>
            {isDeleting ? (
              <>
                <Spinner size="sm" className="me-2" />
                Deleting...
              </>
            ) : (
              <>
                <Trash2 size={14} className="me-1" />
                Delete {selectedScans.length} Scans
              </>
            )}
          </Button>
        </Modal.Footer>
      </Modal>
    </>
  );
};

export default ScanHistory;