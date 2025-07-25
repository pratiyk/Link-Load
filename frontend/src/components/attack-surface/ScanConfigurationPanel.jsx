import React, { useState } from 'react';
import { Play, Settings, Globe, Shield } from 'lucide-react';
import { attackSurfaceAPI } from '../../services/api/attackSurfaceAPI';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';

const ScanConfigurationPanel = () => {
  const navigate = useNavigate();
  const [isLoading, setIsLoading] = useState(false);

  const [config, setConfig] = useState({
    target_domain: '',
    max_subdomains: 1_000,
    port_scan_enabled: true,
    port_range: 'top1000',
    service_detection: true,
    stealth_mode: false,
    api_sources: ['subfinder', 'amass', 'crt', 'dns'],
  });

  const handleInputChange = (field, value) => {
    setConfig((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleCheckboxChange = (field, checked) => {
    setConfig((prev) => ({
      ...prev,
      [field]: checked,
    }));
  };

  const handleSourceToggle = (source) => {
    setConfig((prev) => ({
      ...prev,
      api_sources: prev.api_sources.includes(source)
        ? prev.api_sources.filter((s) => s !== source)
        : [...prev.api_sources, source],
    }));
  };

  const validateConfig = () => {
    if (!config.target_domain.trim()) {
      toast.error('Please enter a target domain');
      return false;
    }

    // Basic domain validation
    const domainPattern = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$/;
    if (!domainPattern.test(config.target_domain.trim())) {
      toast.error('Please enter a valid domain name');
      return false;
    }

    if (config.api_sources.length === 0) {
      toast.error('Please select at least one discovery source');
      return false;
    }

    return true;
  };

  const handleStartScan = async () => {
    if (!validateConfig()) return;

    setIsLoading(true);
    try {
      const result = await attackSurfaceAPI.startScan(config);
      toast.success('Scan started successfully!');
      navigate(`/attack-surface/${result.id}`);
    } catch (error) {
      console.error('Failed to start scan:', error);
      toast.error('Failed to start scan. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-6 bg-white rounded-lg shadow-lg">
      {/* Header */}
      <header className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900 mb-2">
          Attack Surface Mapping Configuration
        </h2>
        <p className="text-gray-600">
          Configure your attack-surface discovery scan parameters
        </p>
      </header>

      {/* Target Domain */}
      <section className="mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          <Globe className="w-4 h-4 inline mr-2" />
          Target Domain
        </label>
        <input
          type="text"
          value={config.target_domain}
          onChange={(e) => handleInputChange('target_domain', e.target.value)}
          placeholder="example.com"
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
        <p className="text-xs text-gray-500 mt-1">
          Enter the root domain you want to map (e.g., example.com)
        </p>
      </section>

      {/* Discovery Sources */}
      <section className="mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-3">
          Discovery Sources
        </label>
        <div className="grid grid-cols-2 gap-3">
          {[
            { id: 'subfinder', name: 'Subfinder', description: 'Fast passive subdomain enumeration' },
            { id: 'amass', name: 'OWASP Amass', description: 'Comprehensive network mapping' },
            { id: 'crt', name: 'Certificate Transparency', description: 'CT log mining' },
            { id: 'dns', name: 'DNS Brute Force', description: 'Dictionary-based discovery' },
          ].map((source) => (
            <div
              key={source.id}
              className={`p-3 border-2 rounded-lg cursor-pointer transition-all ${
                config.api_sources.includes(source.id)
                  ? 'border-blue-500 bg-blue-50'
                  : 'border-gray-200 hover:border-gray-300'
              }`}
              onClick={() => handleSourceToggle(source.id)}
            >
              <div className="flex items-center space-x-2 mb-1">
                <input
                  type="checkbox"
                  checked={config.api_sources.includes(source.id)}
                  readOnly
                  className="text-blue-600"
                />
                <span className="font-medium text-sm">{source.name}</span>
              </div>
              <p className="text-xs text-gray-600">{source.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Scan Limits */}
      <section className="mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-2">
          Maximum Subdomains
        </label>
        <select
          value={config.max_subdomains}
          onChange={(e) => handleInputChange('max_subdomains', parseInt(e.target.value, 10))}
          className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value={100}>100 (Quick scan)</option>
          <option value={500}>500 (Standard scan)</option>
          <option value={1000}>1,000 (Comprehensive scan)</option>
          <option value={5000}>5,000 (Deep scan)</option>
        </select>
      </section>

      {/* Port Scanning Options */}
      <section className="mb-6">
        <div className="flex items-center justify-between mb-3">
          <label className="text-sm font-medium text-gray-700">
            <Shield className="w-4 h-4 inline mr-2" />
            Port Scanning
          </label>
          <input
            type="checkbox"
            checked={config.port_scan_enabled}
            onChange={(e) => handleCheckboxChange('port_scan_enabled', e.target.checked)}
            className="text-blue-600"
          />
        </div>

        {config.port_scan_enabled && (
          <div className="space-y-4 ml-6">
            <div>
              <label className="block text-sm text-gray-600 mb-2">Port Range</label>
              <select
                value={config.port_range}
                onChange={(e) => handleInputChange('port_range', e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="common">Common Ports (Fast)</option>
                <option value="top1000">Top 1,000 Ports (Standard)</option>
                <option value="1-10000">1-10,000 (Comprehensive)</option>
                <option value="all">All Ports (Very Slow)</option>
              </select>
            </div>

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={config.service_detection}
                onChange={(e) => handleCheckboxChange('service_detection', e.target.checked)}
                className="text-blue-600"
              />
              <label className="text-sm text-gray-600">
                Enable service detection and banner grabbing
              </label>
            </div>
          </div>
        )}
      </section>

      {/* Advanced Options */}
      <section className="mb-6">
        <label className="block text-sm font-medium text-gray-700 mb-3">
          <Settings className="w-4 h-4 inline mr-2" />
          Advanced Options
        </label>
        <div className="space-y-3">
          <div className="flex items-center space-x-2">
            <input
              type="checkbox"
              checked={config.stealth_mode}
              onChange={(e) => handleCheckboxChange('stealth_mode', e.target.checked)}
              className="text-blue-600"
            />
            <label className="text-sm text-gray-600">
              Enable stealth mode (slower but less detectable)
            </label>
          </div>
        </div>
      </section>

      {/* Start Scan Button */}
      <footer className="flex justify-end">
        <button
          onClick={handleStartScan}
          disabled={isLoading}
          className={`flex items-center space-x-2 px-6 py-3 rounded-lg font-medium transition-colors ${
            isLoading
              ? 'bg-gray-300 text-gray-500 cursor-not-allowed'
              : 'bg-blue-600 text-white hover:bg-blue-700'
          }`}
        >
          <Play className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          <span>{isLoading ? 'Starting…' : 'Start Scan'}</span>
        </button>
      </footer>
    </div>
  );
};

export default ScanConfigurationPanel;
