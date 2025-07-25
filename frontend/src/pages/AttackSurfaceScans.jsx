import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Plus, Search, Calendar, Globe, AlertTriangle, CheckCircle, Clock, XCircle } from 'lucide-react';
import { attackSurfaceAPI } from '../services/api/attackSurfaceAPI';
import { toast } from 'react-toastify';

const AttackSurfaceScans = () => {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState('');
    const [statusFilter, setStatusFilter] = useState('all');

    useEffect(() => {
        loadScans();
    }, []);

    const loadScans = async () => {
        try {
            const data = await attackSurfaceAPI.getAllScans();
            setScans(data);
        } catch (error) {
            toast.error('Failed to load scans');
            console.error('Error loading scans:', error);
        } finally {
            setLoading(false);
        }
    };

    const getStatusIcon = (status) => {
        switch (status) {
            case 'running':
                return <Clock className="w-4 h-4 text-blue-500 animate-spin" />;
            case 'completed':
                return <CheckCircle className="w-4 h-4 text-green-500" />;
            case 'failed':
                return <XCircle className="w-4 h-4 text-red-500" />;
            case 'cancelled':
                return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
            default:
                return <Clock className="w-4 h-4 text-gray-500" />;
        }
    };

    const getStatusColor = (status) => {
        switch (status) {
            case 'running':
                return 'bg-blue-50 text-blue-700 border-blue-200';
            case 'completed':
                return 'bg-green-50 text-green-700 border-green-200';
            case 'failed':
                return 'bg-red-50 text-red-700 border-red-200';
            case 'cancelled':
                return 'bg-yellow-50 text-yellow-700 border-yellow-200';
            default:
                return 'bg-gray-50 text-gray-700 border-gray-200';
        }
    };

    const filteredScans = scans.filter(scan => {
        const matchesSearch = scan.target_domain.toLowerCase().includes(searchTerm.toLowerCase());
        const matchesStatus = statusFilter === 'all' || scan.status === statusFilter;
        return matchesSearch && matchesStatus;
    });

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-gray-900">Attack Surface Mapping</h2>
                    <p className="text-gray-600">Discover and monitor your external attack surface</p>
                </div>
                <Link
                    to="/attack-surface/new"
                    className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                    <Plus className="w-4 h-4" />
                    <span>New Scan</span>
                </Link>
            </div>

            {/* Filters */}
            <div className="flex items-center space-x-4 bg-white p-4 rounded-lg shadow">
                <div className="flex-1">
                    <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                        <input
                            type="text"
                            placeholder="Search by domain..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="pl-10 pr-4 py-2 w-full border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        />
                    </div>
                </div>
                <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                >
                    <option value="all">All Status</option>
                    <option value="running">Running</option>
                    <option value="completed">Completed</option>
                    <option value="failed">Failed</option>
                    <option value="cancelled">Cancelled</option>
                </select>
            </div>

            {/* Scans List */}
            <div className="space-y-4">
                {filteredScans.length === 0 ? (
                    <div className="text-center py-12 bg-white rounded-lg shadow">
                        <Globe className="mx-auto h-12 w-12 text-gray-400 mb-4" />
                        <h3 className="text-lg font-medium text-gray-900 mb-2">No scans found</h3>
                        <p className="text-gray-600 mb-6">
                            {searchTerm || statusFilter !== 'all' 
                                ? 'Try adjusting your search or filters'
                                : 'Get started by creating your first attack surface scan'
                            }
                        </p>
                        {(!searchTerm && statusFilter === 'all') && (
                            <Link
                                to="/attack-surface/new"
                                className="inline-flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                            >
                                <Plus className="w-4 h-4" />
                                <span>Create First Scan</span>
                            </Link>
                        )}
                    </div>
                ) : (
                    filteredScans.map((scan) => (
                        <Link
                            key={scan.id}
                            to={`/attack-surface/${scan.id}`}
                            className="block bg-white rounded-lg shadow hover:shadow-md transition-shadow"
                        >
                            <div className="p-6">
                                <div className="flex items-center justify-between mb-4">
                                    <div className="flex items-center space-x-3">
                                        <Globe className="w-6 h-6 text-blue-500" />
                                        <div>
                                            <h3 className="text-lg font-semibold text-gray-900">
                                                {scan.target_domain}
                                            </h3>
                                            <p className="text-sm text-gray-600">
                                                Scan ID: {scan.id.slice(0, 8)}...
                                            </p>
                                        </div>
                                    </div>
                                    <div className={`inline-flex items-center space-x-2 px-3 py-1 rounded-full border text-sm font-medium ${getStatusColor(scan.status)}`}>
                                        {getStatusIcon(scan.status)}
                                        <span className="capitalize">{scan.status}</span>
                                    </div>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                                    <div className="text-center">
                                        <div className="text-2xl font-bold text-gray-900">
                                            {scan.total_assets_found || 0}
                                        </div>
                                        <div className="text-sm text-gray-600">Assets Found</div>
                                    </div>
                                    <div className="text-center">
                                        <div className="text-2xl font-bold text-red-600">
                                            {scan.high_risk_assets || 0}
                                        </div>
                                        <div className="text-sm text-gray-600">High Risk</div>
                                    </div>
                                    <div className="text-center">
                                        <div className="text-2xl font-bold text-blue-600">
                                            {scan.progress || 0}%
                                        </div>
                                        <div className="text-sm text-gray-600">Progress</div>
                                    </div>
                                    <div className="text-center">
                                        <div className="text-sm font-medium text-gray-900">
                                            <Calendar className="w-4 h-4 inline mr-1" />
                                            {new Date(scan.created_at).toLocaleDateString()}
                                        </div>
                                        <div className="text-sm text-gray-600">Created</div>
                                    </div>
                                </div>

                                {scan.status === 'running' && (
                                    <div className="w-full bg-gray-200 rounded-full h-2">
                                        <div
                                            className="bg-blue-500 h-2 rounded-full transition-all duration-300"
                                            style={{ width: `${scan.progress || 0}%` }}
                                        />
                                    </div>
                                )}
                            </div>
                        </Link>
                    ))
                )}
            </div>
        </div>
    );
};

export default AttackSurfaceScans;
