import {render, screen, waitFor} from '@testing-library/react';
import App                       from './App';
import React                     from "react";
import {MemoryRouter}            from 'react-router-dom';
import {AuthProvider, useAuth}   from './authContext';
import Box                       from "@mui/material/Box";
import api                       from './api/apiClient';

jest.mock('./api/apiClient', () => {
    return {
        setupRequired: jest.fn().mockResolvedValue({required: false}),
        loggedIn: jest.fn().mockResolvedValue({username: 'testuser'}),
    }
})


jest.mock('./authContext', () => ({
    ...jest.requireActual('./authContext'),
    useAuth: jest.fn(),
}));

describe('App Component', () => {
    const renderApp = (initialEntries = ['']) => {

        return render(
            <MemoryRouter initialEntries={initialEntries}>
                <AuthProvider>
                    <Box>
                        <App/>
                    </Box>
                </AuthProvider>
            </MemoryRouter>
        );

    };

    beforeEach(() => {
        // Reset the mock before each test
        (useAuth as jest.Mock).mockReset();
    });


    test('renders MenuLinkBar', () => {
        (useAuth as jest.Mock).mockReturnValue({
            isAuthenticated: true,
            login: jest.fn(),
            logout: jest.fn(),
            username: 'testuser',
            setupRequired: false,
        });

        renderApp();
        const linkBar = screen.getByText('DisConcierge');
        expect(linkBar).toBeInTheDocument();
    });

    test('renders Login component when not authenticated', async () => {
        (useAuth as jest.Mock).mockReturnValue({
            isAuthenticated: false,
            login: jest.fn(),
            logout: jest.fn(),
            username: null,
            setupRequired: false,
        });

        const {debug} = renderApp(['/login']);

        console.log('render:');
        debug();
        // Wait for the component to render
        await waitFor(() => {
            expect(screen.getByText('Sign In')).toBeInTheDocument();
        });

        // Try different ways to find the button
        const signInButton = screen.getByRole('button', {name: /sign in/i}) ||
            screen.getByText(/sign in/i, {selector: 'button'}) ||
            screen.getByText(/sign in/i);

        expect(signInButton).toBeInTheDocument();
    });

    test('redirects to main when authenticated', async () => {
        // Mock useAuth to return authenticated state
        (useAuth as jest.Mock).mockReturnValue({
            isAuthenticated: true,
            login: jest.fn(),
            logout: jest.fn(),
            username: 'testuser',
            setupRequired: false,
        });

        renderApp(['/login']);

        await waitFor(() => {

            const signInButton = screen.getByRole('button', {name: /log out/i}) ||
                screen.getByText(/log out/i, {selector: 'button'}) ||
                screen.getByText(/log out/i);

            expect(signInButton).toBeInTheDocument();

        });
    });

    test('redirects to login when accessing protected route while not authenticated', () => {
        (useAuth as jest.Mock).mockReturnValue({
            isAuthenticated: false,
            login: jest.fn(),
            logout: jest.fn(),
            username: null,
            setupRequired: false,
        });

        renderApp(['/config']);
        const loginButton = screen.getByRole('button', {name: /sign in/i});
        expect(loginButton).toBeInTheDocument();
    });

    test('renders MainPage component when authenticated and on root route', async () => {
        (useAuth as jest.Mock).mockReturnValue({
            isAuthenticated: true,
            login: jest.fn(),
            logout: jest.fn(),
            username: 'testuser',
            setupRequired: false,
        });


        const {debug} = render(
            <MemoryRouter initialEntries={['/']}>
                <AuthProvider>
                    <App/>
                </AuthProvider>
            </MemoryRouter>
        );

        console.log('Initial render:');
        debug();

        await waitFor(() => {
            console.log('Render after waiting:');
            // debug();

            expect(screen.getByText('Go to Users')).toBeInTheDocument();
            expect(screen.getByText('Go to Commands')).toBeInTheDocument();

        });

    });

    test('renders FirstTimeSetup component when setup is required', async () => {
        (api.setupRequired as jest.Mock).mockResolvedValue({required: true});
        (useAuth as jest.Mock).mockReturnValue({
            isAuthenticated: false,
            login: jest.fn(),
            logout: jest.fn(),
            username: null,
            setupRequired: true,
        });


        const {debug} = renderApp();
        debug();
        await waitFor(() => {
            const setupTitle = screen.getByText('First-Time Setup');
            expect(setupTitle).toBeInTheDocument();

            expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
            // expect(screen.getByLabelText(/Password/)).toBeInTheDocument();
            expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument();
            expect(screen.getByRole('button', {name: /create admin user/i})).toBeInTheDocument();

            debug();
        });

    });
});