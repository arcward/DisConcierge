import React                        from 'react';
import ProtectedRoute               from './components/ProtectedRoute';
import Login                        from './components/Login';
import AppMenu                      from './components/AppMenu';
import {Route, Routes}              from "react-router-dom";
import axios                        from 'axios';
import {createTheme, ThemeProvider} from '@mui/material/styles';
import Main                         from './components/Main';
import Users                        from './components/UsersList';
import RuntimeConfigView            from './components/RuntimeConfig';
import Box                          from "@mui/material/Box";
import CssBaseline                  from "@mui/material/CssBaseline";
import '@fontsource/roboto/300.css';
import '@fontsource/roboto/400.css';
import '@fontsource/roboto/500.css';
import '@fontsource/roboto/700.css';
import Toolbar                      from "@mui/material/Toolbar";
import {AuthProvider, useAuth}      from './authContext';
import ChatCommandsList             from './components/ChatCommandList';
import DiscordMessageList           from './components/DiscordMessageList';
import NotFound                     from './components/NotFound';
import SnackbarProvider             from './alertLoadingContext';
import UserFeedbackList             from './components/UserFeedbackList';
import ChatCommandView              from './components/ChatCommandView';
import UserFeedbackView             from './components/UserFeedbackView';

axios.defaults.withCredentials = true;

const darkTheme = createTheme({
    palette: {
        mode: 'dark',
    },
});

// TODO: error visibility for things like 404s from backend API calls


const AppRoutes = () => {
    const {isLoading} = useAuth();

    if (isLoading) {
        return <div>Loading...</div>;
    }

    return (
        <Routes>

            <Route path="/login" element={<Login/>}/>

            <Route path="/" element={<ProtectedRoute><Main/></ProtectedRoute>}/>
            <Route path="/users" element={<ProtectedRoute><Users/></ProtectedRoute>}/>
            <Route path="/config"
                   element={<ProtectedRoute><RuntimeConfigView/></ProtectedRoute>}/>
            <Route path="/chat_commands"
                   element={<ProtectedRoute><ChatCommandsList/></ProtectedRoute>}/>
            <Route path="/discord_messages"
                   element={<ProtectedRoute><DiscordMessageList/></ProtectedRoute>}/>
            <Route path="/user_feedback"
                   element={<ProtectedRoute><UserFeedbackList/></ProtectedRoute>}/>
            <Route path="/chat_command/:id"
                   element={<ProtectedRoute><ChatCommandView/></ProtectedRoute>}/>
            <Route path="/user_feedback/:id"
                   element={<ProtectedRoute><UserFeedbackView/></ProtectedRoute>}/>
            <Route path="*" element={<NotFound/>}/>


        </Routes>
    );
};


const App = () => {
    return (
        <ThemeProvider theme={darkTheme}>
            <CssBaseline/>
            <SnackbarProvider>
                <AuthProvider>
                    <Box>
                        <Box component="main" sx={{pl: 2, pb: 2, pr: 2, pt: '32px'}}>
                            <Toolbar/>
                            <AppRoutes/>
                        </Box>
                        <AppMenu/>
                    </Box>
                </AuthProvider>
            </SnackbarProvider>
        </ThemeProvider>
    );
};

export default App;
