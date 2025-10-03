import React from "react";
import { Form, Row, Col, Accordion } from "react-bootstrap";

const ScanConfiguration = ({ config, setConfig }) => {
  const scannerOptions = [
    { id: "zap_active", label: "OWASP ZAP (Active Scan)", description: "Comprehensive active scanning for vulnerabilities" },
    { id: "nuclei", label: "Nuclei", description: "Fast and customizable vulnerability scanning" },
    { id: "wapiti", label: "Wapiti", description: "Web application vulnerability scanner" },
  ];

  const handleScanTypeChange = (scannerId) => {
    setConfig(prev => {
      const newTypes = prev.scan_types.includes(scannerId)
        ? prev.scan_types.filter(id => id !== scannerId)
        : [...prev.scan_types, scannerId];
      
      return { ...prev, scan_types: newTypes };
    });
  };

  return (
    <div>
      <h4 className="mb-4">Scan Configuration</h4>
      
      <Form.Group className="mb-4">
        <Form.Label>Target URL</Form.Label>
        <Form.Control
          type="url"
          placeholder="https://example.com"
          value={config.target_url}
          onChange={(e) => setConfig({ ...config, target_url: e.target.value })}
          required
        />
        <Form.Text className="text-muted">
          Enter the full URL of the website you want to scan
        </Form.Text>
      </Form.Group>
      
      <Form.Group className="mb-4">
        <Form.Label>Security Scanners</Form.Label>
        <div className="border rounded p-3">
          {scannerOptions.map((scanner) => (
            <Form.Check 
              key={scanner.id}
              type="checkbox"
              id={`scanner-${scanner.id}`}
              label={
                <div>
                  <strong>{scanner.label}</strong>
                  <div className="text-muted small">{scanner.description}</div>
                </div>
              }
              checked={config.scan_types.includes(scanner.id)}
              onChange={() => handleScanTypeChange(scanner.id)}
              className="mb-2"
            />
          ))}
        </div>
      </Form.Group>
      
      <Accordion className="mb-4">
        <Accordion.Item eventKey="0">
          <Accordion.Header>Advanced Settings</Accordion.Header>
          <Accordion.Body>
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Scan Depth</Form.Label>
                  <Form.Select
                    value={config.scan_depth}
                    onChange={(e) => setConfig({ ...config, scan_depth: parseInt(e.target.value) })}
                  >
                    <option value={1}>Level 1 (Shallow)</option>
                    <option value={2}>Level 2 (Standard)</option>
                    <option value={3}>Level 3 (Deep)</option>
                    <option value={4}>Level 4 (Very Deep)</option>
                    <option value={5}>Level 5 (Maximum)</option>
                  </Form.Select>
                  <Form.Text className="text-muted">
                    How deep should the scanner crawl the website
                  </Form.Text>
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Max Scan Time (minutes)</Form.Label>
                  <Form.Control
                    type="number"
                    min="5"
                    max="120"
                    value={config.max_scan_time / 60}
                    onChange={(e) => setConfig({ 
                      ...config, 
                      max_scan_time: parseInt(e.target.value) * 60 
                    })}
                  />
                  <Form.Text className="text-muted">
                    Maximum duration for the scan (5-120 minutes)
                  </Form.Text>
                </Form.Group>
              </Col>
            </Row>
            
            <Form.Check
              type="switch"
              id="include-low-risk"
              label="Include low-risk vulnerabilities in results"
              checked={config.include_low_risk}
              onChange={(e) => setConfig({ ...config, include_low_risk: e.target.checked })}
              className="mb-3"
            />
          </Accordion.Body>
        </Accordion.Item>
      </Accordion>
    </div>
  );
};

export default ScanConfiguration;