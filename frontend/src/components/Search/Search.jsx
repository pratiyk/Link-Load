import React, { useState } from 'react';
import './Search.css';

const Search = ({ onSearch, placeholder = "Scan a URL or domain..." }) => {
  const [query, setQuery] = useState('');
  const [isFocused, setIsFocused] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (query.trim()) {
      onSearch(query.trim());
    }
  };

  return (
    <div className={`search-container ${isFocused ? 'focused' : ''}`}>
      <form onSubmit={handleSubmit} className="search-form">
        <div className="search-input-wrapper">
          <svg className="search-icon" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
            <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/>
          </svg>
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onFocus={() => setIsFocused(true)}
            onBlur={() => setIsFocused(false)}
            placeholder={placeholder}
            className="search-input"
            aria-label="Search input"
          />
          {query && (
            <button
              type="button"
              className="clear-button"
              onClick={() => setQuery('')}
              aria-label="Clear search"
            >
              <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
                <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/>
              </svg>
            </button>
          )}
        </div>
        <button type="submit" className="search-button" disabled={!query.trim()}>
          Scan Now
        </button>
      </form>
      
      <div className="search-suggestions">
        <div className="suggestion-label">Quick Scans:</div>
        <div className="suggestion-chips">
          <button 
            type="button" 
            className="suggestion-chip"
            onClick={() => {
              setQuery('https://');
              document.querySelector('.search-input').focus();
            }}
          >
            HTTPS URL
          </button>
          <button 
            type="button" 
            className="suggestion-chip"
            onClick={() => {
              setQuery('domain.com');
              document.querySelector('.search-input').focus();
            }}
          >
            Domain Name
          </button>
        </div>
      </div>
    </div>
  );
};

export default Search;