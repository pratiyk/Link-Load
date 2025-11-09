import React from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../components/Layout';
import './NotFound.css';

const NotFound = () => {
  const navigate = useNavigate();

  return (
    <Layout>
      <div className="notfound-container">
        <div className="notfound-content">
          <div className="error-code-block">
            <div className="code-display">404</div>
            <div className="glitch-overlay">404</div>
          </div>

          <div className="error-message-section">
            <h1 className="error-title">PAGE NOT FOUND</h1>
            <p className="error-description">
              The page you're looking for doesn't exist or has been moved.
              It might have been removed, renamed, or didn't exist in the first place.
            </p>

            <div className="error-actions">
              <button onClick={() => navigate('/')} className="btn-home">
                RETURN HOME
              </button>
              <button onClick={() => navigate(-1)} className="btn-back">
                GO BACK
              </button>
            </div>
          </div>

          <div className="error-visual">
            <div className="broken-link-graphic">
              <div className="link-segment segment-1"></div>
              <div className="link-break"></div>
              <div className="link-segment segment-2"></div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default NotFound;