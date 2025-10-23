import React from 'react';
import '../styles/layout.css';

const Layout = ({ children }) => {
  // Prevent layout shift during image load
  React.useEffect(() => {
    const img = new Image();
    img.src = '/assets/Untitled_Design__2_-removebg-preview.png';
  }, []);
  
  return (
    <div className="layout">
      <nav className="sidebar">
        <div className="logo-container">
          <img 
            src="/assets/Untitled_Design__2_-removebg-preview.png" 
            alt="Link&Load Logo" 
            className="logo" 
          />
        </div>
        
        <div className="nav-items">
          <div className="folder-item">
            <span className="folder-number">01.</span>
            <span className="folder-name">Business</span>
            <button className="folder-menu">:</button>
          </div>
          
          <div className="folder-item">
            <span className="folder-number">02.</span>
            <span className="folder-name">HR</span>
            <button className="folder-menu">:</button>
          </div>
          
          <div className="folder-item">
            <span className="folder-number">03.</span>
            <span className="folder-name">Resources</span>
            <button className="folder-menu">:</button>
          </div>
          
          <div className="folder-item">
            <span className="folder-number">04.</span>
            <span className="folder-name">Temp</span>
            <button className="folder-menu">:</button>
          </div>
        </div>
      </nav>

      <main className="main-content">
        <header className="top-nav">
          <div className="nav-links">
            <a href="#services" className="nav-link">SERVICES</a>
            <a href="#work" className="nav-link">WORK</a>
            <a href="#connect" className="nav-link">CONNECT</a>
            <a href="#store" className="nav-link">STORE</a>
          </div>
          <button className="help-button">Press ? for help</button>
        </header>

        <div className="content-area">
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;