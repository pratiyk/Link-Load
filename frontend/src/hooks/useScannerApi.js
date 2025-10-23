import { useState, useCallback } from 'react';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL;

export const useScannerApi = () => {
    const [loading, setLoading] = useState(false);

    const startScan = useCallback(async (config) => {
        setLoading(true);
        try {
            const response = await axios.post(`${API_BASE_URL}/scans`, config);
            return response.data;
        } finally {
            setLoading(false);
        }
    }, []);

    const listScans = useCallback(async (params = {}) => {
        setLoading(true);
        try {
            const response = await axios.get(`${API_BASE_URL}/scans`, { params });
            return response.data;
        } finally {
            setLoading(false);
        }
    }, []);

    const getScanStatus = useCallback(async (scanId) => {
        const response = await axios.get(`${API_BASE_URL}/scans/${scanId}`);
        return response.data;
    }, []);

    const cancelScan = useCallback(async (scanId) => {
        const response = await axios.delete(`${API_BASE_URL}/scans/${scanId}`);
        return response.data;
    }, []);

    const getScanFindings = useCallback(async (scanId, params = {}) => {
        const response = await axios.get(
            `${API_BASE_URL}/scans/${scanId}/findings`,
            { params }
        );
        return response.data;
    }, []);

    const scheduleRecurringScan = useCallback(async (config) => {
        const response = await axios.post(
            `${API_BASE_URL}/scans/schedule`,
            config
        );
        return response.data;
    }, []);

    return {
        loading,
        startScan,
        listScans,
        getScanStatus,
        cancelScan,
        getScanFindings,
        scheduleRecurringScan
    };
};