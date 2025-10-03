import React from 'react';
import { Link } from 'react-router-dom';
import { Button } from 'react-bootstrap';

const NotFound = () => {
  return (
    <div className="container text-center py-5">
      <h1 className="display-1">404</h1>
      <p className="lead">Oops! Page not found</p>
      <p>The page you're looking for doesn't exist or has been moved.</p>
      <Button as={Link} to="/" variant="primary">
        Go to Homepage
      </Button>
    </div>
  );
};

export default NotFound;