import React from 'react';
import '../styles/layout.css';

const Layout = ({ children }) => {
  return (
    <div className="layout">
      <main className="main-content">
        <div className="content-area">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;
