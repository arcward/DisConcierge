import '@testing-library/jest-dom';

// Mock environment variables
process.env.REACT_APP_API_HOST = 'http://localhost';
process.env.REACT_APP_API_PORT = '3000';

// Mock window.location
const mockWindow = window as any;
mockWindow.location = {
    ...mockWindow.location,
    href: 'http://localhost',
};

// Add custom function to window.location
Object.defineProperty(mockWindow.location, 'endsWith', {
    value: jest.fn(),
    configurable: true,
});