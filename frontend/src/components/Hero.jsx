import React from 'react';
import '../styles/retro.css';

const Hero = () => {
  return (
    <section className="hero">
      <div className="game-console floating">
        <div className="screen-effect">
          {/* Your game screen content */}
        </div>
      </div>
      
      <div className="hero-content">
        <h1 className="heading-large pixel-text">
          The Unmistakably
          <br />
          Original Design
          <span className="retro-bubble">Studio</span>
        </h1>
        
        <p className="year-text pixel-text">
          Creating Experiences Since 2015
        </p>
      </div>
    </section>
  );
};

export default Hero;