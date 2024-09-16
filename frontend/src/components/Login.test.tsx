import React                                from 'react';
import {fireEvent, render, screen, waitFor} from '@testing-library/react';
import Login                                from './Login';
import {AuthProvider, useAuth}              from '../authContext';
import {createTheme, ThemeProvider}         from "@mui/material/styles";
import {BrowserRouter as Router}            from 'react-router-dom';


jest.mock('../authContext', () => ({
    ...jest.requireActual('../authContext'),
    useAuth: jest.fn(),
}));

jest.mock('../api/apiClient', () => ({

    loggedIn: jest.fn().mockResolvedValue({username: 'testuser'}),
}));

const mockLogin = jest.fn();


const customRender = (ui: React.ReactElement, {providerProps = {}, ...renderOptions} = {}) => {
    const theme = createTheme();
    return render(
        <ThemeProvider theme={theme}>
            <Router>
                <AuthProvider {...providerProps}>{ui}</AuthProvider>
            </Router>
        </ThemeProvider>,
        renderOptions
    );
};


describe('Login Component', () => {
    beforeEach(() => {
        (useAuth as jest.Mock).mockReturnValue({
            login: mockLogin,
            isAuthenticated: false,
        });
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    it('renders login form', () => {
        customRender(<Login/>);

        expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/password/i)).toBeInTheDocument();
        expect(screen.getByRole('button', {name: /sign in/i})).toBeInTheDocument();
    });

    it('handles form submission', async () => {
        customRender(<Login/>);

        fireEvent.change(screen.getByLabelText(/username/i), {target: {value: 'testuser'}});
        fireEvent.change(screen.getByLabelText(/password/i), {target: {value: 'password123'}});

        fireEvent.click(screen.getByRole('button', {name: /sign in/i}));

        await waitFor(() => {
            expect(mockLogin).toHaveBeenCalledWith('testuser', 'password123');
        });
    });
});