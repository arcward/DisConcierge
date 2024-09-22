import React, {useEffect, useState} from 'react';
import {useNavigate}                from 'react-router-dom';

import Button     from '@mui/material/Button';
import TextField  from '@mui/material/TextField';
import Box        from '@mui/material/Box';
import Typography from '@mui/material/Typography';
import {Snackbar} from "@mui/material";
import Alert      from '@mui/material/Alert';
import {useAuth}  from '../authContext';


const Login = () => {
    const history = useNavigate();
    const [open, setOpen] = React.useState(false);
    const [apiError, setApiError] = useState('');
    const {login, isAuthenticated} = useAuth();

    const handleClose = (event: any) => {
        setOpen(false);
    };

    const handleSubmit = async (event: any) => {
        event.preventDefault();

        try {
            const data: any = new FormData(event.currentTarget);
            login(data.get('username'), data.get('password'));
        } catch (error) {
            console.log(error);
            setApiError(`Error logging in: ${error}`);
            setOpen(true);

        }
    };

    useEffect(() => {
        if (isAuthenticated) {
            history('/');
        }
    }, [isAuthenticated, history]);

    return (
        <Box
            sx={{
                marginTop: 8, display: 'flex', flexDirection: 'column', alignItems: 'center',
            }}
        >
            <Typography component="h1" variant="h5">
                Sign in
            </Typography>
            <Box component="form" onSubmit={handleSubmit} noValidate sx={{mt: 1}}>
                <TextField
                    margin="normal"
                    required
                    fullWidth
                    id="username"
                    label="Username"
                    name="username"
                    autoComplete="username"
                    autoFocus
                />
                <TextField
                    margin="normal"
                    required
                    fullWidth
                    name="password"
                    label="Password"
                    type="password"
                    id="password"
                    autoComplete="current-password"
                />
                <Button
                    type="submit"
                    fullWidth
                    variant="contained"
                    name="sign in"
                    role="button"
                    sx={{mt: 3, mb: 2}}
                >
                    Sign In
                </Button>
            </Box>
            <Snackbar open={open} onClose={handleClose}>
                <Alert
                    onClose={e => handleClose(e)}
                    severity="error"
                    variant="filled"
                    sx={{width: '100%'}}
                >
                    {apiError}
                </Alert>
            </Snackbar>
        </Box>

    );
};

export default Login;
