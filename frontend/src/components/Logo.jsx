import React from 'react';
import './Logo.css';

const Logo = () => {
  return (
    <div className="logo">
      <svg width="48" height="48" viewBox="0 0 500 500" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M100 250 C 200 150, 300 350, 400 250" stroke="#967bdc" strokeWidth="40" fill="none"/>
        <path d="M150 300 L 200 300 L 200 350 L 150 350 L 150 300" fill="#967bdc"/>
        <path d="M250 300 L 300 300 L 300 350 L 250 350 L 250 300" fill="#967bdc"/>
        <path d="M350 300 L 400 300 L 400 350 L 350 350 L 350 300" fill="#967bdc"/>
      </svg>
    </div>
  );
};

export default Logo;