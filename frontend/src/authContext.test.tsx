import React                        from 'react';
import {act, render}                from '@testing-library/react';
import {AuthProvider, useAuth}      from './authContext';
import api                          from './api/apiClient';
import {createTheme, ThemeProvider} from "@mui/material/styles";
import {MemoryRouter as Router}     from 'react-router-dom';

// Mock the api
jest.mock('./api/apiClient', () => ({
    setupRequired: jest.fn().mockResolvedValue({required: false}),
    loggedIn: jest.fn().mockResolvedValue({username: 'testuser'}),
}));


describe('AuthProvider', () => {
    it('initializes correctly', async () => {
        (api.setupRequired as jest.Mock).mockResolvedValue({required: false});
        (api.loggedIn as jest.Mock).mockResolvedValue({username: 'testuser'});

        let testSetupRequired;
        let testIsAuthenticated;
        let testUsername;

        const TestComponent = () => {
            const {setupRequired, isAuthenticated, username} = useAuth();
            testSetupRequired = setupRequired;
            testIsAuthenticated = isAuthenticated;
            testUsername = username;

            return null;
        };

        const theme = createTheme();

        await act(async () => {
            render(
                <ThemeProvider theme={theme}>
                    <Router>

                        <AuthProvider>

                            <TestComponent/>
                        </AuthProvider>
                    </Router>

                </ThemeProvider>
            );
        });

        expect(testSetupRequired).toBe(false);
        expect(testIsAuthenticated).toBe(true);
        expect(testUsername).toBe('testuser');
    });
});