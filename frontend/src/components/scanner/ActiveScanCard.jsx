import React from 'react';
import { Card, Progress, Button, Badge } from '@supabase/ui';
import { formatDistanceToNow } from 'date-fns';

const ActiveScanCard = ({ scan, onCancel }) => {
    const getStatusColor = (status) => {
        switch (status) {
            case 'running':
                return 'green';
            case 'pending':
                return 'blue';
            default:
                return 'gray';
        }
    };

    const formatProgress = (progress) => {
        if (!progress) return null;

        return {
            percent: progress.progress_percentage || 0,
            current: progress.scanned_urls || 0,
            total: progress.total_urls || 0,
            findings: progress.vulnerabilities_found || 0,
            step: progress.current_step || 'Initializing',
            timeRemaining: progress.estimated_time_remaining
        };
    };

    const progress = formatProgress(scan.progress);

    return (
        <Card>
            <Card.Header className="flex justify-between items-center">
                <div>
                    <h3 className="text-lg font-medium">{scan.target_url}</h3>
                    <Badge color={getStatusColor(scan.status)}>
                        {scan.status.toUpperCase()}
                    </Badge>
                </div>
                <Button
                    type="danger"
                    onClick={() => onCancel(scan.id)}
                >
                    Cancel
                </Button>
            </Card.Header>

            <Card.Body>
                <div className="space-y-4">
                    <div>
                        <div className="flex justify-between mb-2">
                            <span className="text-sm font-medium">
                                {progress?.step}
                            </span>
                            <span className="text-sm text-gray-500">
                                {progress?.percent.toFixed(1)}%
                            </span>
                        </div>
                        <Progress
                            value={progress?.percent || 0}
                            color={getStatusColor(scan.status)}
                            size="large"
                        />
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <span className="text-sm text-gray-500">URLs Scanned</span>
                            <p className="text-lg font-medium">
                                {progress?.current} / {progress?.total}
                            </p>
                        </div>
                        <div>
                            <span className="text-sm text-gray-500">Findings</span>
                            <p className="text-lg font-medium">
                                {progress?.findings}
                            </p>
                        </div>
                    </div>

                    <div className="flex justify-between text-sm text-gray-500">
                        <span>Started {formatDistanceToNow(new Date(scan.started_at))} ago</span>
                        {progress?.timeRemaining && (
                            <span>
                                ~{Math.ceil(progress.timeRemaining / 60)} minutes remaining
                            </span>
                        )}
                    </div>

                    <div className="flex flex-wrap gap-2">
                        {scan.scan_types.map(type => (
                            <Badge key={type}>{type}</Badge>
                        ))}
                    </div>
                </div>
            </Card.Body>
        </Card>
    );
};

export default ActiveScanCard;