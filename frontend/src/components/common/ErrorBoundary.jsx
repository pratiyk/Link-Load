import React from 'react';
import { Card, Button } from '@supabase/ui';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { 
            hasError: false,
            error: null,
            errorInfo: null
        };
    }

    static getDerivedStateFromError(error) {
        return { hasError: true };
    }

    componentDidCatch(error, errorInfo) {
        this.setState({
            error: error,
            errorInfo: errorInfo
        });
        
        // Log error to your error tracking service
        console.error('Error caught by boundary:', error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <Card className="p-6 m-4">
                    <Card.Header>
                        <h2 className="text-xl font-bold text-red-600">
                            Something went wrong
                        </h2>
                    </Card.Header>
                    <Card.Body>
                        <div className="space-y-4">
                            <p className="text-gray-600">
                                An error occurred in this component.
                            </p>
                            {process.env.NODE_ENV === 'development' && (
                                <details className="mt-4">
                                    <summary className="cursor-pointer text-sm text-gray-500">
                                        Technical Details
                                    </summary>
                                    <pre className="mt-2 p-4 bg-gray-100 rounded text-sm overflow-auto">
                                        {this.state.error?.toString()}
                                        {'\n'}
                                        {this.state.errorInfo?.componentStack}
                                    </pre>
                                </details>
                            )}
                            <Button
                                type="default"
                                onClick={() => window.location.reload()}
                            >
                                Reload Page
                            </Button>
                        </div>
                    </Card.Body>
                </Card>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;