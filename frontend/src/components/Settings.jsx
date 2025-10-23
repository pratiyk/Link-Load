import React from 'react';

const Settings = ({ settings, onSettingChange, onClose }) => {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal pixel-border" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3 className="pixel-text">SETTINGS</h3>
          <button className="close-btn pixel-text" onClick={onClose}>×</button>
        </div>
        <div className="modal-content">
          <div className="settings-grid">
            <label className="pixel-checkbox">
              <input
                type="checkbox"
                checked={settings.darkMode}
                onChange={e => onSettingChange('darkMode', e.target.checked)}
              />
              <span className="checkbox-text">DARK MODE</span>
            </label>
            <label className="pixel-checkbox">
              <input
                type="checkbox"
                checked={settings.notifications}
                onChange={e => onSettingChange('notifications', e.target.checked)}
              />
              <span className="checkbox-text">NOTIFICATIONS</span>
            </label>
            <label className="pixel-checkbox">
              <input
                type="checkbox"
                checked={settings.autoScan}
                onChange={e => onSettingChange('autoScan', e.target.checked)}
              />
              <span className="checkbox-text">AUTO SCAN</span>
            </label>
            <div className="setting-item">
              <label className="pixel-text">SCAN INTERVAL (MIN)</label>
              <input
                type="number"
                className="pixel-input"
                value={settings.scanInterval}
                onChange={e => onSettingChange('scanInterval', parseInt(e.target.value) || 0)}
              />
            </div>
          </div>
        </div>
        <div className="modal-footer">
          <button className="btn btn-primary pixel-btn" onClick={onClose}>
            SAVE SETTINGS
          </button>
        </div>
      </div>
    </div>
  );
};

export default Settings;