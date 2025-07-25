import React from 'react';
import { Shield, Globe, Server, AlertTriangle, Info } from 'lucide-react';

const AssetDetailsPanel = ({ asset }) => {
    if (!asset) {
        return (
            <div className="p-6 text-center text-gray-500">
                <Globe className="w-12 h-12 mx-auto mb-4 text-gray-300" />
                <p>Select an asset to view details</p>
            </div>
        );
    }

    const getRiskColor = (level) => {
        const colors = {
            low: 'text-green-600 bg-green-50',
            medium: 'text-yellow-600 bg-yellow-50',
            high: 'text-orange-600 bg-orange-50',
            critical: 'text-red-600 bg-red-50'
        };
        return colors[level] || colors.low;
    };

    const getRiskIcon = (level) => {
        if (level === 'critical' || level === 'high') {
            return <AlertTriangle className="w-4 h-4" />;
        }
        return <Shield className="w-4 h-4" />;
    };

    return (
        <div className="p-6 overflow-y-auto">
            {/* Asset Header */}
            <div className="mb-6">
                <div className="flex items-center justify-between mb-2">
                    <h2 className="text-lg font-semibold text-gray-900 truncate">
                        {asset.name}
                    </h2>
                    <span className={`inline-flex items-center space-x-1 px-2 py-1 rounded-full text-xs font-medium ${getRiskColor(asset.risk_level)}`}>
                        {getRiskIcon(asset.risk_level)}
                        <span>{asset.risk_level.toUpperCase()}</span>
                    </span>
                </div>
                <p className="text-sm text-gray-600">
                    {asset.asset_type.replace('_', ' ').toUpperCase()}
                </p>
                <div className="mt-2">
                    <span className="text-sm font-medium text-gray-700">Risk Score: </span>
                    <span className="text-sm text-gray-900">{asset.risk_score.toFixed(1)}/10</span>
                </div>
            </div>

            {/* Basic Information */}
            <div className="mb-6">
                <h3 className="text-sm font-medium text-gray-700 mb-3">Basic Information</h3>
                <div className="space-y-2">
                    {asset.ip_address && (
                        <div className="flex justify-between">
                            <span className="text-sm text-gray-600">IP Address:</span>
                            <span className="text-sm font-mono text-gray-900">{asset.ip_address}</span>
                        </div>
                    )}
                    <div className="flex justify-between">
                        <span className="text-sm text-gray-600">Discovered:</span>
                        <span className="text-sm text-gray-900">
                            {new Date(asset.discovered_at).toLocaleDateString()}
                        </span>
                    </div>
                    <div className="flex justify-between">
                        <span className="text-sm text-gray-600">Last Seen:</span>
                        <span className="text-sm text-gray-900">
                            {new Date(asset.last_seen).toLocaleDateString()}
                        </span>
                    </div>
                </div>
            </div>

            {/* Open Ports */}
            {asset.ports && asset.ports.length > 0 && (
                <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">Open Ports</h3>
                    <div className="grid grid-cols-3 gap-2">
                        {asset.ports.map(port => (
                            <span
                                key={port}
                                className="inline-flex items-center justify-center px-2 py-1 rounded bg-blue-50 text-blue-700 text-xs font-medium"
                            >
                                {port}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Services */}
            {asset.services && Object.keys(asset.services).length > 0 && (
                <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">Services</h3>
                    <div className="space-y-3">
                        {Object.entries(asset.services).map(([port, service]) => (
                            <div key={port} className="border border-gray-200 rounded-lg p-3">
                                <div className="flex items-center justify-between mb-2">
                                    <span className="font-medium text-sm">Port {port}</span>
                                    <Server className="w-4 h-4 text-gray-400" />
                                </div>
                                <div className="space-y-1 text-xs text-gray-600">
                                    <div>Service: {service.service || 'Unknown'}</div>
                                    {service.version && (
                                        <div>Version: {service.version}</div>
                                    )}
                                    {service.banner && (
                                        <div className="font-mono bg-gray-50 p-2 rounded truncate">
                                            {service.banner}
                                        </div>
                                    )}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Risk Factors */}
            {asset.risk_factors && asset.risk_factors.length > 0 && (
                <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">Risk Factors</h3>
                    <div className="space-y-2">
                        {asset.risk_factors.map((factor, index) => (
                            <div key={index} className="flex items-center space-x-2 text-sm">
                                <AlertTriangle className="w-4 h-4 text-orange-500" />
                                <span className="text-gray-700">{factor}</span>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Vulnerabilities */}
            {asset.vulnerabilities && asset.vulnerabilities.length > 0 && (
                <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">Known Vulnerabilities</h3>
                    <div className="space-y-2">
                        {asset.vulnerabilities.map((vuln, index) => (
                            <div key={index} className="border-l-4 border-red-400 pl-3 py-2 bg-red-50">
                                <div className="font-medium text-sm text-red-800">
                                    {vuln.id || vuln.cve_id}
                                </div>
                                <div className="text-xs text-red-600">
                                    Severity: {vuln.severity || 'Unknown'}
                                </div>
                                {vuln.description && (
                                    <div className="text-xs text-red-700 mt-1">
                                        {vuln.description}
                                    </div>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* SSL Information */}
            {asset.ssl_info && Object.keys(asset.ssl_info).length > 0 && (
                <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">SSL Certificate</h3>
                    <div className="space-y-2 text-sm">
                        {asset.ssl_info.issuer && (
                            <div className="flex justify-between">
                                <span className="text-gray-600">Issuer:</span>
                                <span className="text-gray-900 text-right">{asset.ssl_info.issuer}</span>
                            </div>
                        )}
                        {asset.ssl_info.expires && (
                            <div className="flex justify-between">
                                <span className="text-gray-600">Expires:</span>
                                <span className="text-gray-900">
                                    {new Date(asset.ssl_info.expires).toLocaleDateString()}
                                </span>
                            </div>
                        )}
                        {asset.ssl_info.valid && (
                            <div className="flex justify-between">
                                <span className="text-gray-600">Valid:</span>
                                <span className={asset.ssl_info.valid ? 'text-green-600' : 'text-red-600'}>
                                    {asset.ssl_info.valid ? 'Yes' : 'No'}
                                </span>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Technologies */}
            {asset.technologies && asset.technologies.length > 0 && (
                <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">Technologies</h3>
                    <div className="flex flex-wrap gap-2">
                        {asset.technologies.map((tech, index) => (
                            <span
                                key={index}
                                className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-50 text-purple-700"
                            >
                                {tech}
                            </span>
                        ))}
                    </div>
                </div>
            )}

            {/* Geolocation */}
            {asset.geolocation && Object.keys(asset.geolocation).length > 0 && (
                <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">Location</h3>
                    <div className="space-y-2 text-sm">
                        {asset.geolocation.country && (
                            <div className="flex justify-between">
                                <span className="text-gray-600">Country:</span>
                                <span className="text-gray-900">{asset.geolocation.country}</span>
                            </div>
                        )}
                        {asset.geolocation.city && (
                            <div className="flex justify-between">
                                <span className="text-gray-600">City:</span>
                                <span className="text-gray-900">{asset.geolocation.city}</span>
                            </div>
                        )}
                        {asset.geolocation.org && (
                            <div className="flex justify-between">
                                <span className="text-gray-600">Organization:</span>
                                <span className="text-gray-900 text-right">{asset.geolocation.org}</span>
                            </div>
                        )}
                    </div>
                </div>
            )}

            {/* Threat Intelligence */}
            {asset.threat_intel && Object.keys(asset.threat_intel).length > 0 && (
                <div className="mb-6">
                    <h3 className="text-sm font-medium text-gray-700 mb-3">Threat Intelligence</h3>
                    <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                        <div className="flex items-center space-x-2 mb-2">
                            <Info className="w-4 h-4 text-yellow-600" />
                            <span className="text-sm font-medium text-yellow-800">
                                Additional Intelligence Available
                            </span>
                        </div>
                        <div className="text-xs text-yellow-700">
                            This asset has additional threat intelligence data available from external sources.
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AssetDetailsPanel;
