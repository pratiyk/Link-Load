import { useEffect, useRef, useState } from 'react';

export const useWebSocket = (url) => {
    const [connectionStatus, setConnectionStatus] = useState('Connecting');
    const [lastMessage, setLastMessage] = useState(null);
    const ws = useRef(null);
    const reconnectTimeoutId = useRef(null);
    const maxReconnectAttempts = 5;
    const reconnectAttempts = useRef(0);

    useEffect(() => {
        const connect = () => {
            try {
                ws.current = new WebSocket(url);

                ws.current.onopen = () => {
                    console.log('WebSocket connected');
                    setConnectionStatus('Connected');
                    reconnectAttempts.current = 0;
                };

                ws.current.onmessage = (event) => {
                    setLastMessage(event);
                };

                ws.current.onclose = (event) => {
                    console.log('WebSocket disconnected:', event.code, event.reason);
                    setConnectionStatus('Disconnected');

                    // Attempt to reconnect if not a clean close
                    if (event.code !== 1000 && reconnectAttempts.current < maxReconnectAttempts) {
                        reconnectAttempts.current += 1;
                        const timeout = Math.pow(2, reconnectAttempts.current) * 1000; // Exponential backoff
                        
                        console.log(`Reconnecting in ${timeout}ms... (Attempt ${reconnectAttempts.current})`);
                        setConnectionStatus(`Reconnecting... (${reconnectAttempts.current}/${maxReconnectAttempts})`);
                        
                        reconnectTimeoutId.current = setTimeout(() => {
                            connect();
                        }, timeout);
                    } else if (reconnectAttempts.current >= maxReconnectAttempts) {
                        setConnectionStatus('Failed to reconnect');
                    }
                };

                ws.current.onerror = (error) => {
                    console.error('WebSocket error:', error);
                    setConnectionStatus('Error');
                };

            } catch (error) {
                console.error('Failed to create WebSocket connection:', error);
                setConnectionStatus('Failed to connect');
            }
        };

        connect();

        return () => {
            if (reconnectTimeoutId.current) {
                clearTimeout(reconnectTimeoutId.current);
            }
            if (ws.current) {
                ws.current.close(1000, 'Component unmounting');
            }
        };
    }, [url]);

    const sendMessage = (message) => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            ws.current.send(JSON.stringify(message));
            return true;
        }
        console.warn('WebSocket is not connected');
        return false;
    };

    const closeConnection = () => {
        if (ws.current) {
            ws.current.close(1000, 'Manual close');
        }
    };

    return {
        connectionStatus,
        lastMessage,
        sendMessage,
        closeConnection
    };
};
