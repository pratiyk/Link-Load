import React from 'react';
import '../styles/retro.css';

const Header = () => {
  return (
    <header className="nav">
      <div className="logo pixel-text">TA</div>
      <nav className="nav-links">
        <a href="#services" className="nav-link">Services</a>
        <a href="#work" className="nav-link">Work</a>
        <a href="#connect" className="nav-link">Connect</a>
        <a href="#store" className="nav-link">Store</a>
      </nav>
      <div className="help-text pixel-text">Press ? for help</div>
    </header>
  );
};

export default Header;