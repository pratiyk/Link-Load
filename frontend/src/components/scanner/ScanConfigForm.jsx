import React, { useState } from 'react';
import { Input, Button, Checkbox, Card, Select } from '@supabase/ui';
import { useForm, Controller } from 'react-hook-form';

const ScanConfigForm = ({ onSubmit }) => {
    const { register, handleSubmit, control, formState: { errors } } = useForm({
        defaultValues: {
            target_url: '',
            scan_types: [],
            scan_config: {
                scan_depth: 'normal',
                concurrent_requests: 10,
                request_delay: 0.1,
                auth_required: false,
                excluded_paths: [],
                scan_timeout: 3600
            }
        }
    });

    const scanTypes = [
        { value: 'zap', label: 'OWASP ZAP' },
        { value: 'nuclei', label: 'Nuclei' },
        { value: 'wapiti', label: 'Wapiti' },
        { value: 'nikto', label: 'Nikto' }
    ];

    const scanDepths = [
        { value: 'quick', label: 'Quick Scan' },
        { value: 'normal', label: 'Normal Scan' },
        { value: 'deep', label: 'Deep Scan' }
    ];

    return (
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
            <div>
                <label className="block text-sm font-medium text-gray-700">
                    Target URL
                </label>
                <Input
                    {...register('target_url', {
                        required: 'Target URL is required',
                        pattern: {
                            value: /^https?:\/\/.+/,
                            message: 'Must be a valid URL starting with http:// or https://'
                        }
                    })}
                    placeholder="https://example.com"
                    error={errors.target_url?.message}
                />
            </div>

            <div>
                <label className="block text-sm font-medium text-gray-700">
                    Scan Types
                </label>
                <Controller
                    name="scan_types"
                    control={control}
                    rules={{ required: 'Select at least one scan type' }}
                    render={({ field }) => (
                        <Select
                            {...field}
                            options={scanTypes}
                            isMulti
                            error={errors.scan_types?.message}
                        />
                    )}
                />
            </div>

            <Card>
                <Card.Header>
                    <h3 className="text-lg font-medium">Advanced Configuration</h3>
                </Card.Header>
                <Card.Body>
                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-gray-700">
                                Scan Depth
                            </label>
                            <Controller
                                name="scan_config.scan_depth"
                                control={control}
                                render={({ field }) => (
                                    <Select
                                        {...field}
                                        options={scanDepths}
                                    />
                                )}
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-700">
                                Concurrent Requests
                            </label>
                            <Input
                                type="number"
                                {...register('scan_config.concurrent_requests', {
                                    min: { value: 1, message: 'Must be at least 1' },
                                    max: { value: 50, message: 'Maximum 50 concurrent requests' }
                                })}
                                error={errors.scan_config?.concurrent_requests?.message}
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-700">
                                Request Delay (seconds)
                            </label>
                            <Input
                                type="number"
                                step="0.1"
                                {...register('scan_config.request_delay', {
                                    min: { value: 0, message: 'Must be non-negative' },
                                    max: { value: 5, message: 'Maximum 5 seconds delay' }
                                })}
                                error={errors.scan_config?.request_delay?.message}
                            />
                        </div>

                        <div>
                            <Controller
                                name="scan_config.auth_required"
                                control={control}
                                render={({ field }) => (
                                    <Checkbox
                                        {...field}
                                        label="Authentication Required"
                                    />
                                )}
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-700">
                                Excluded Paths (one per line)
                            </label>
                            <textarea
                                className="mt-1 block w-full rounded-md border-gray-300 shadow-sm"
                                rows="3"
                                {...register('scan_config.excluded_paths')}
                                placeholder="/admin/*&#10;/api/internal/*"
                            />
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-gray-700">
                                Scan Timeout (seconds)
                            </label>
                            <Input
                                type="number"
                                {...register('scan_config.scan_timeout', {
                                    min: { value: 300, message: 'Minimum 5 minutes' },
                                    max: { value: 86400, message: 'Maximum 24 hours' }
                                })}
                                error={errors.scan_config?.scan_timeout?.message}
                            />
                        </div>
                    </div>
                </Card.Body>
            </Card>

            <div className="flex justify-end">
                <Button
                    type="submit"
                    size="large"
                    className="w-full sm:w-auto"
                >
                    Start Scan
                </Button>
            </div>
        </form>
    );
};

export default ScanConfigForm;