import React from 'react';
import '../styles/layout.css';

const Layout = ({ children }) => {
    const currentYear = new Date().getFullYear();

    return (
        <div className="layout">
            <main className="main-content">
                <div className="content-area">
                    {children}
                </div>
                <footer className="tactical-footer">
                    <div className="footer-content">
                        <div className="footer-callsign">
                            <span className="footer-bracket">[</span>
                            <span className="footer-label">LINKLOAD</span>
                            <span className="footer-bracket">]</span>
                            <span className="footer-divider">//</span>
                            <span className="footer-status">OPEN SOURCE RECONNAISSANCE PLATFORM</span>
                        </div>
                        <div className="footer-credits">
                            <span className="footer-operator">Operator: Prateek Shrivastava</span>
                            <span className="footer-divider">|</span>
                            <span className="footer-year">Field Deployed {currentYear}</span>
                        </div>
                    </div>
                </footer>

            </main>
        </div>
    );
};

export default Layout;
