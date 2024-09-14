import React, {useState}                           from 'react';
import {Alert, Box, Button, TextField, Typography} from '@mui/material';
import api                                         from '../api/apiClient';
import {useAuth}                                   from '../authContext';

interface FirstTimeSetupProps {
    onSetupComplete: () => void;
}

const FirstTimeSetup: React.FC<FirstTimeSetupProps> = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [error, setError] = useState('');
    const [success, setSuccess] = useState(false);
    const {setSetupRequired} = useAuth();

    const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setError('');

        if (password !== confirmPassword) {
            setError("Passwords don't match");
            return;
        }

        try {
            await api.createAdminUser({
                username: username,
                password: password,
                confirm_password: confirmPassword
            });
            setSuccess(true);
            setSetupRequired(false);
            // onSetupComplete ();
        } catch (error) {
            setError(`An error occurred while creating the admin user: ${error}`);
        }
    };

    if (success) {
        return (
            <Box sx={{maxWidth: 400, margin: 'auto', mt: 4, textAlign: 'center'}}>
                <Alert severity="success">
                    Admin user created successfully! You can now log in.
                </Alert>
            </Box>
        );
    }

    return (
        <Box sx={{maxWidth: 400, margin: 'auto', mt: 4}}>
            <Typography variant="h4" component="h1" gutterBottom>
                First-Time Setup
            </Typography>
            <Typography variant="body1" gutterBottom>
                Create your admin account to get started.
            </Typography>
            <form onSubmit={handleSubmit}>
                <TextField
                    fullWidth
                    margin="normal"
                    label="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                />
                <TextField
                    fullWidth
                    margin="normal"
                    label="Password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                />
                <TextField
                    fullWidth
                    margin="normal"
                    label="Confirm Password"
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                />
                {error && (
                    <Alert severity="error" sx={{mt: 2}}>
                        {error}
                    </Alert>
                )}
                <Button
                    type="submit"
                    variant="contained"
                    color="primary"
                    fullWidth
                    role="button"
                    sx={{mt: 2}}
                >
                    Create Admin User
                </Button>
            </form>
        </Box>
    );
};

export default FirstTimeSetup;