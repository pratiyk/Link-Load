import React, { useState } from 'react';
import { Card, Badge, Button, Collapse } from '@supabase/ui';
import { formatDistanceToNow } from 'date-fns';
import {
    Chart as ChartJS,
    ArcElement,
    Tooltip,
    Legend,
    CategoryScale,
    LinearScale,
    BarElement
} from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';

ChartJS.register(
    ArcElement,
    Tooltip,
    Legend,
    CategoryScale,
    LinearScale,
    BarElement
);

const SeverityBadge = ({ severity }) => {
    const colors = {
        critical: 'red',
        high: 'orange',
        medium: 'yellow',
        low: 'blue',
        info: 'gray'
    };

    return (
        <Badge color={colors[severity.toLowerCase()]}>
            {severity.toUpperCase()}
        </Badge>
    );
};

const VulnerabilityChart = ({ summary }) => {
    const data = {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
            data: [
                summary.critical_count,
                summary.high_count,
                summary.medium_count,
                summary.low_count,
                summary.info_count
            ],
            backgroundColor: [
                '#ef4444',
                '#f97316',
                '#eab308',
                '#3b82f6',
                '#9ca3af'
            ]
        }]
    };

    const options = {
        responsive: true,
        plugins: {
            legend: {
                position: 'bottom'
            }
        }
    };

    return <Pie data={data} options={options} />;
};

const ComplianceChart = ({ summary }) => {
    const data = {
        labels: ['Risk Score', 'Compliance Score', 'Coverage'],
        datasets: [{
            data: [
                summary.risk_score * 100,
                summary.compliance_score * 100,
                summary.scan_coverage * 100
            ],
            backgroundColor: ['#ef4444', '#22c55e', '#3b82f6']
        }]
    };

    const options = {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true,
                max: 100,
                ticks: {
                    callback: value => `${value}%`
                }
            }
        },
        plugins: {
            legend: {
                display: false
            }
        }
    };

    return <Bar data={data} options={options} />;
};

const ScanResults = ({ scan }) => {
    const [showDetails, setShowDetails] = useState(false);

    if (!scan.summary) {
        return null;
    }

    return (
        <Card>
            <Card.Header className="flex justify-between items-center">
                <div>
                    <h3 className="text-lg font-medium truncate" title={scan.target_url}>
                        {scan.target_url}
                    </h3>
                    <div className="text-sm text-gray-500">
                        {formatDistanceToNow(new Date(scan.completed_at))} ago
                    </div>
                </div>
                <Badge color={scan.status === 'completed' ? 'green' : 'red'}>
                    {scan.status.toUpperCase()}
                </Badge>
            </Card.Header>

            <Card.Body>
                <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4 text-center">
                        <div>
                            <div className="text-2xl font-bold">
                                {scan.summary.total_vulnerabilities}
                            </div>
                            <div className="text-sm text-gray-500">Total Findings</div>
                        </div>
                        <div>
                            <div className="text-2xl font-bold">
                                {(scan.summary.risk_score * 10).toFixed(1)}
                            </div>
                            <div className="text-sm text-gray-500">Risk Score</div>
                        </div>
                    </div>

                    <div className="h-40">
                        <VulnerabilityChart summary={scan.summary} />
                    </div>

                    <Button
                        block
                        type="default"
                        onClick={() => setShowDetails(!showDetails)}
                    >
                        {showDetails ? 'Hide Details' : 'Show Details'}
                    </Button>

                    <Collapse open={showDetails}>
                        <div className="space-y-4 pt-4">
                            <div className="h-40">
                                <ComplianceChart summary={scan.summary} />
                            </div>

                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <div className="text-sm text-gray-500">Scan Types</div>
                                    <div className="flex flex-wrap gap-2 mt-1">
                                        {scan.scan_types.map(type => (
                                            <Badge key={type}>{type}</Badge>
                                        ))}
                                    </div>
                                </div>
                                <div>
                                    <div className="text-sm text-gray-500">Duration</div>
                                    <div>
                                        {formatDistanceToNow(
                                            new Date(scan.completed_at) - new Date(scan.started_at)
                                        )}
                                    </div>
                                </div>
                            </div>

                            {scan.errors?.length > 0 && (
                                <div>
                                    <div className="text-sm text-gray-500">Errors</div>
                                    <div className="mt-1 text-red-600">
                                        {scan.errors.join(', ')}
                                    </div>
                                </div>
                            )}
                        </div>
                    </Collapse>
                </div>
            </Card.Body>
        </Card>
    );
};

export default ScanResults;