import React from 'react';
import { Clock, CheckCircle, XCircle, AlertCircle } from 'lucide-react';

const ScanProgress = ({ scan }) => {
    const getStatusIcon = () => {
        switch (scan.status) {
            case 'running':
                return <Clock className="w-4 h-4 text-blue-500 animate-spin" />;
            case 'completed':
                return <CheckCircle className="w-4 h-4 text-green-500" />;
            case 'failed':
                return <XCircle className="w-4 h-4 text-red-500" />;
            case 'cancelled':
                return <AlertCircle className="w-4 h-4 text-yellow-500" />;
            default:
                return <Clock className="w-4 h-4 text-gray-500" />;
        }
    };

    const getStatusColor = () => {
        switch (scan.status) {
            case 'running':
                return 'bg-blue-500';
            case 'completed':
                return 'bg-green-500';
            case 'failed':
                return 'bg-red-500';
            case 'cancelled':
                return 'bg-yellow-500';
            default:
                return 'bg-gray-500';
        }
    };

    const getStageText = () => {
        const progress = scan.progress || 0;
        
        if (progress < 25) return 'Discovering subdomains...';
        if (progress < 50) return 'Creating asset inventory...';
        if (progress < 75) return 'Scanning ports and services...';
        if (progress < 100) return 'Enriching with threat intelligence...';
        return 'Scan completed!';
    };

    return (
        <div className="mt-4">
            <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-2">
                    {getStatusIcon()}
                    <span className="text-sm font-medium text-gray-700">
                        {getStageText()}
                    </span>
                </div>
                <span className="text-sm text-gray-600">
                    {scan.progress || 0}%
                </span>
            </div>
            
            <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                    className={`h-2 rounded-full transition-all duration-300 ${getStatusColor()}`}
                    style={{ width: `${scan.progress || 0}%` }}
                />
            </div>
            
            {scan.error_message && (
                <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded text-sm text-red-700">
                    Error: {scan.error_message}
                </div>
            )}
        </div>
    );
};

export default ScanProgress;
