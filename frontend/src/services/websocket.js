import { createContext, useContext, useEffect, useState } from 'react';

const WebSocketContext = createContext(null);

export class WebSocketService {
    constructor(baseURL) {
        this.baseURL = baseURL;
        this.socket = null;
        this.subscribers = new Map();
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 2000;
    }

    connect(scanId, token) {
        if (this.socket?.readyState === WebSocket.OPEN) {
            this.socket.close();
        }

        const wsUrl = `${this.baseURL}/ws/scans/${scanId}?token=${token}`;
        this.socket = new WebSocket(wsUrl);

        this.socket.onopen = () => {
            console.log('WebSocket connected');
            this.reconnectAttempts = 0;
        };

        this.socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.notifySubscribers(message);
            } catch (error) {
                console.error('Error parsing WebSocket message:', error);
            }
        };

        this.socket.onclose = () => {
            console.log('WebSocket disconnected');
            this.handleReconnect(scanId, token);
        };

        this.socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    handleReconnect(scanId, token) {
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            setTimeout(() => {
                console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})`);
                this.connect(scanId, token);
            }, this.reconnectDelay * this.reconnectAttempts);
        } else {
            this.notifySubscribers({
                type: 'error',
                message: 'WebSocket connection failed after multiple attempts'
            });
        }
    }

    subscribe(id, callback) {
        this.subscribers.set(id, callback);
    }

    unsubscribe(id) {
        this.subscribers.delete(id);
    }

    notifySubscribers(message) {
        this.subscribers.forEach(callback => callback(message));
    }

    disconnect() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
        }
        this.subscribers.clear();
    }
}

export const WebSocketProvider = ({ children }) => {
    const [wsService] = useState(() => new WebSocketService(process.env.REACT_APP_WS_URL));

    useEffect(() => {
        return () => wsService.disconnect();
    }, [wsService]);

    return (
        <WebSocketContext.Provider value={wsService}>
            {children}
        </WebSocketContext.Provider>
    );
};

export const useWebSocket = () => {
    const context = useContext(WebSocketContext);
    if (!context) {
        throw new Error('useWebSocket must be used within a WebSocketProvider');
    }
    return context;
};