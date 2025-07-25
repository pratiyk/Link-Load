import React, { useState, useEffect, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import { toast } from 'react-toastify';
import NetworkGraph from './NetworkGraph';
import AssetDetailsPanel from './AssetDetailsPanel';
import ScanProgress from './ScanProgress';
import RiskHeatmap from './RiskHeatmap';
import { attackSurfaceAPI } from '../../services/api/attackSurfaceAPI';
import { useWebSocket } from '../../services/websocket/scanProgressSocket';

const AttackSurfaceMap = () => {
    const { scanId } = useParams();
    const [scan, setScan] = useState(null);
    const [assets, setAssets] = useState([]);
    const [selectedAsset, setSelectedAsset] = useState(null);
    const [loading, setLoading] = useState(true);
    const [filter, setFilter] = useState({
        assetType: 'all',
        riskLevel: 'all',
        searchTerm: ''
    });

    // WebSocket for real-time updates
    const { lastMessage, connectionStatus } = useWebSocket(
        `ws://localhost:8000/api/v1/attack-surface/scan/${scanId}/ws`
    );

    // Load scan data
    const loadScanData = useCallback(async () => {
        try {
            const [scanData, assetsData] = await Promise.all([
                attackSurfaceAPI.getScanStatus(scanId),
                attackSurfaceAPI.getScanAssets(scanId)
            ]);
            
            setScan(scanData);
            setAssets(assetsData);
            setLoading(false);
        } catch (error) {
            toast.error('Failed to load scan data');
            console.error('Error loading scan data:', error);
            setLoading(false);
        }
    }, [scanId]);

    // Handle WebSocket messages
    useEffect(() => {
        if (lastMessage) {
            const message = JSON.parse(lastMessage.data);
            
            switch (message.type) {
                case 'progress':
                    setScan(prev => ({
                        ...prev,
                        progress: message.data.progress
                    }));
                    break;
                    
                case 'asset_discovered':
                    // Refresh assets when new ones are discovered
                    loadScanData();
                    toast.info(`New asset discovered: ${message.data.asset}`);
                    break;
                    
                case 'scan_complete':
                    setScan(prev => ({
                        ...prev,
                        status: 'completed',
                        progress: 100
                    }));
                    toast.success('Scan completed successfully!');
                    break;
                    
                case 'error':
                    toast.error(`Scan error: ${message.data.error}`);
                    break;
                    
                default:
                    break;
            }
        }
    }, [lastMessage, loadScanData]);

    // Load data on mount
    useEffect(() => {
        loadScanData();
    }, [loadScanData]);

    // Filter assets
    const filteredAssets = assets.filter(asset => {
        const matchesType = filter.assetType === 'all' || asset.asset_type === filter.assetType;
        const matchesRisk = filter.riskLevel === 'all' || asset.risk_level === filter.riskLevel;
        const matchesSearch = !filter.searchTerm || 
            asset.name.toLowerCase().includes(filter.searchTerm.toLowerCase());
        
        return matchesType && matchesRisk && matchesSearch;
    });

    // Prepare network graph data
    const networkData = {
        nodes: filteredAssets.map(asset => ({
            id: asset.id,
            name: asset.name,
            type: asset.asset_type,
            riskScore: asset.risk_score,
            riskLevel: asset.risk_level,
            ports: asset.ports,
            services: asset.services
        })),
        links: [] // You can add relationship data here
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-screen">
                <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
            </div>
        );
    }

    return (
        <div className="h-screen flex flex-col">
            {/* Header */}
            <div className="bg-white shadow-sm border-b border-gray-200 p-4">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-gray-900">
                            Attack Surface Map
                        </h1>
                        <p className="text-sm text-gray-600">
                            Target: {scan?.target_domain} | Status: {scan?.status}
                        </p>
                    </div>
                    
                    {/* Connection Status */}
                    <div className="flex items-center space-x-4">
                        <div className={`flex items-center space-x-2 ${
                            connectionStatus === 'Connected' ? 'text-green-600' : 'text-red-600'
                        }`}>
                            <div className={`w-2 h-2 rounded-full ${
                                connectionStatus === 'Connected' ? 'bg-green-500' : 'bg-red-500'
                            }`}></div>
                            <span className="text-sm">{connectionStatus}</span>
                        </div>
                        
                        <button
                            onClick={loadScanData}
                            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700"
                        >
                            Refresh
                        </button>
                    </div>
                </div>
                
                {/* Progress Bar */}
                {scan && scan.status === 'running' && (
                    <ScanProgress scan={scan} />
                )}
            </div>

            {/* Filters */}
            <div className="bg-gray-50 border-b border-gray-200 p-4">
                <div className="flex items-center space-x-4">
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Asset Type</label>
                        <select
                            value={filter.assetType}
                            onChange={(e) => setFilter(prev => ({ ...prev, assetType: e.target.value }))}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                        >
                            <option value="all">All Types</option>
                            <option value="subdomain">Subdomains</option>
                            <option value="ip_address">IP Addresses</option>
                            <option value="service">Services</option>
                        </select>
                    </div>
                    
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Risk Level</label>
                        <select
                            value={filter.riskLevel}
                            onChange={(e) => setFilter(prev => ({ ...prev, riskLevel: e.target.value }))}
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                        >
                            <option value="all">All Levels</option>
                            <option value="critical">Critical</option>
                            <option value="high">High</option>
                            <option value="medium">Medium</option>
                            <option value="low">Low</option>
                        </select>
                    </div>
                    
                    <div className="flex-1">
                        <label className="block text-sm font-medium text-gray-700">Search</label>
                        <input
                            type="text"
                            value={filter.searchTerm}
                            onChange={(e) => setFilter(prev => ({ ...prev, searchTerm: e.target.value }))}
                            placeholder="Search assets..."
                            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                        />
                    </div>
                </div>
            </div>

            {/* Main Content */}
            <div className="flex-1 flex">
                {/* Network Graph */}
                <div className="flex-1 relative">
                    <NetworkGraph
                        data={networkData}
                        onNodeClick={setSelectedAsset}
                        selectedNode={selectedAsset}
                    />
                </div>
                
                {/* Side Panel */}
                <div className="w-96 border-l border-gray-200 bg-white flex flex-col">
                    {/* Asset Details */}
                    <div className="flex-1">
                        <AssetDetailsPanel asset={selectedAsset} />
                    </div>
                    
                    {/* Risk Heatmap */}
                    <div className="h-64 border-t border-gray-200">
                        <RiskHeatmap assets={filteredAssets} />
                    </div>
                </div>
            </div>

            {/* Stats Footer */}
            <div className="bg-gray-50 border-t border-gray-200 p-4">
                <div className="flex items-center justify-between text-sm text-gray-600">
                    <div>
                        Total Assets: {assets.length} | 
                        Filtered: {filteredAssets.length} |
                        High Risk: {assets.filter(a => ['high', 'critical'].includes(a.risk_level)).length}
                    </div>
                    <div>
                        Last Updated: {new Date().toLocaleTimeString()}
                    </div>
                </div>
            </div>
        </div>
    );
};

export default AttackSurfaceMap;
