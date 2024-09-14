import React, {createContext, ReactNode, useContext, useEffect, useState} from 'react';
import api                                                                from './api/apiClient';
import {useLocation, useNavigate}                                         from "react-router-dom";

interface AuthContextType {
    isAuthenticated: boolean;
    isLoading: boolean | null;
    username: string | null;
    login: (username: string, password: string) => void;
    logout: () => void;

    setupRequired: boolean | null;
    setSetupRequired: (setupRequired: boolean) => void
}


const AuthContext = createContext<AuthContextType | undefined>(undefined);


export const AuthProvider: React.FC<{ children: ReactNode }> = ({children}) => {
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const history = useNavigate();
    const [username, setUsername] = useState<string | null>(null)

    const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
    const location = useLocation();
    const [isLoading, setIsLoading] = useState(true);

    const login = (username: string, password: string) => {
        api.login(username, password).then(result => {
            console.log('logged in', result);
            setUsername(result.username)
            setIsAuthenticated(true);
            history('/');
        }).catch(error => {
            console.error('Error logging out', error);
        });
    };

    const logout = () => {
        setIsAuthenticated(false);
        setUsername('');
        api.logout().then(result => {
            history("/login");
        }).catch(error => {
            console.error('Error logging out', error);
        });
    };


    useEffect(() => {
        const initializeApp = async () => {
            setIsLoading(true);
            try {
                // First, check if the app is set up
                const setupResponse = await api.setupRequired();
                setSetupRequired(setupResponse?.required ?? false);

                // If the app is set up, then check authentication
                if (!setupResponse?.required) {
                    try {
                        const authResponse = await api.loggedIn();
                        setIsAuthenticated(true);
                        setUsername(authResponse?.username ?? null);
                    } catch (error) {
                        setIsAuthenticated(false);
                        setUsername(null);
                    }
                }
            } catch (error) {
                console.error('Error initializing app:', error);
                setSetupRequired(false);
                setIsAuthenticated(false);
                setUsername(null);
            } finally {
                setIsLoading(false);
            }
        };
        initializeApp().then(r => console.log('initialized app'));
    }, []);

    useEffect(() => {
        if (isLoading) {
            return;
        }

        if (setupRequired === true && location.pathname.indexOf('/setup') < 0) {
            history('/setup');
        } else if (setupRequired === false && !isAuthenticated && location.pathname.indexOf('/login') < 0) {
            history('/login');
        }
    }, [setupRequired, isAuthenticated, location.pathname, history, isLoading]);

    const value = {
        isAuthenticated,
        username,
        login,
        logout,
        setupRequired,
        setSetupRequired,
        isLoading,
    };
    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextType => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider');
    }
    return context;
};