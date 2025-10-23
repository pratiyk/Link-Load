import React, { useState, useEffect } from 'react';
import { Card, Button, Alert, Progress } from '@supabase/ui';
import ScanConfigForm from './ScanConfigForm';
import ScanResults from './ScanResults';
import ActiveScanCard from './ActiveScanCard';
import { useWebSocket } from '../../services/websocket';
import { useScannerApi } from '../../hooks/useScannerApi';

const ScannerDashboard = () => {
    // Health check effect
    useEffect(() => {
        const checkHealth = async () => {
            try {
                const response = await fetch('/api/health');
                const health = await response.json();
                
                if (health.status !== 'healthy') {
                    setError('System health check failed. Please check dependencies.');
                    console.error('Health check details:', health);
                }
            } catch (err) {
                setError('Failed to verify system health');
                console.error('Health check error:', err);
            }
        };
        
        checkHealth();
    }, []);
    const [activeScans, setActiveScans] = useState([]);
    const [completedScans, setCompletedScans] = useState([]);
    const [error, setError] = useState(null);
    const wsService = useWebSocket();
    const { startScan, listScans, cancelScan } = useScannerApi();

    useEffect(() => {
        loadScans();
        return () => {
            activeScans.forEach(scan => wsService.disconnect(scan.id));
        };
    }, []);

    const loadScans = async () => {
        try {
            const scans = await listScans();
            setActiveScans(scans.filter(s => ['pending', 'running'].includes(s.status)));
            setCompletedScans(scans.filter(s => ['completed', 'failed', 'cancelled'].includes(s.status)));
        } catch (err) {
            setError('Failed to load scans');
            console.error(err);
        }
    };

    const handleStartScan = async (config) => {
        try {
            setError(null);
            const scan = await startScan(config);
            setActiveScans(prev => [...prev, scan]);
            wsService.connect(scan.id);
        } catch (err) {
            setError('Failed to start scan');
            console.error(err);
        }
    };

    const handleCancelScan = async (scanId) => {
        try {
            await cancelScan(scanId);
            setActiveScans(prev => prev.filter(s => s.id !== scanId));
            loadScans();
        } catch (err) {
            setError('Failed to cancel scan');
            console.error(err);
        }
    };

    const handleScanUpdate = (scanId, update) => {
        if (update.type === 'progress') {
            setActiveScans(prev => prev.map(scan => 
                scan.id === scanId 
                    ? { ...scan, progress: update.data }
                    : scan
            ));
        } else if (update.type === 'completion') {
            setActiveScans(prev => prev.filter(s => s.id !== scanId));
            loadScans();
        }
    };

    return (
        <div className="p-6 space-y-6">
            <h1 className="text-2xl font-bold mb-6">Security Scanner</h1>
            
            {error && (
                <Alert type="error" title="Error" message={error} />
            )}

            <Card>
                <Card.Header>
                    <h2 className="text-xl font-semibold">New Scan</h2>
                </Card.Header>
                <Card.Body>
                    <ScanConfigForm onSubmit={handleStartScan} />
                </Card.Body>
            </Card>

            {activeScans.length > 0 && (
                <div className="space-y-4">
                    <h2 className="text-xl font-semibold">Active Scans</h2>
                    {activeScans.map(scan => (
                        <ActiveScanCard
                            key={scan.id}
                            scan={scan}
                            onCancel={() => handleCancelScan(scan.id)}
                        />
                    ))}
                </div>
            )}

            {completedScans.length > 0 && (
                <div className="space-y-4">
                    <h2 className="text-xl font-semibold">Recent Scans</h2>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                        {completedScans.map(scan => (
                            <ScanResults key={scan.id} scan={scan} />
                        ))}
                    </div>
                </div>
            )}
        </div>
    );
};

export default ScannerDashboard;