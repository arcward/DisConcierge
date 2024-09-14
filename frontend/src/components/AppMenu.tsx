import React, {useState}          from 'react';
import disconcierge_icon          from '../assets/disconcierge_icon.png';
import Box                        from "@mui/material/Box";
import Toolbar                    from "@mui/material/Toolbar";
import Typography                 from "@mui/material/Typography";
import Button                     from "@mui/material/Button";
import AppBar                     from "@mui/material/AppBar";
import {useLocation, useNavigate} from "react-router-dom";
import {useAuth}                  from '../authContext';
import IconButton                 from '@mui/material/IconButton';
import Menu                       from '@mui/material/Menu';
import MenuItem                   from '@mui/material/MenuItem';
import MenuIcon                   from '@mui/icons-material/Menu';
import useMediaQuery              from '@mui/material/useMediaQuery';
import {useTheme}                 from '@mui/material/styles';

import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import api                   from '../api/apiClient';
import Dialog                from '@mui/material/Dialog';
import DialogActions         from '@mui/material/DialogActions';
import DialogContent         from '@mui/material/DialogContent';
import DialogContentText     from '@mui/material/DialogContentText';
import DialogTitle           from '@mui/material/DialogTitle';
import Snackbar              from '@mui/material/Snackbar';
import Alert           from '@mui/material/Alert';
import {Divider, Link} from "@mui/material";


const AppMenu = () => {
    const history = useNavigate();
    const location = useLocation();
    const {isAuthenticated, logout} = useAuth();
    const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
    const theme = useTheme();
    const isMobile = useMediaQuery(theme.breakpoints.down('sm'));


    const [actionsAnchorEl, setActionsAnchorEl] = useState<null | HTMLElement>(null);
    const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
    const [confirmAction, setConfirmAction] = useState<() => Promise<void>>(() => Promise.resolve());
    const [confirmMessage, setConfirmMessage] = useState('');
    const [alertOpen, setAlertOpen] = useState(false);
    const [alertMessage, setAlertMessage] = useState('');
    const [alertSeverity, setAlertSeverity] = useState<'success' | 'error'>('success');
    const [databaseAnchorEl, setDatabaseAnchorEl] = useState<null | HTMLElement>(null);


    const handleDatabaseMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
        setDatabaseAnchorEl(event.currentTarget);
    };

    const handleDatabaseMenuClose = () => {
        setDatabaseAnchorEl(null);
    };


    const handleMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
        setAnchorEl(event.currentTarget);
    };

    const handleMenuClose = () => {
        setAnchorEl(null);
    };

    const handleNavigation = (path: string) => {
        history(path);
        handleMenuClose();
        handleActionsMenuClose();
        handleDatabaseMenuClose();
    };

    const handleActionsMenuOpen = (event: React.MouseEvent<HTMLElement>) => {
        setActionsAnchorEl(event.currentTarget);
    };

    const handleActionsMenuClose = () => {
        setActionsAnchorEl(null);
    };

    const handleConfirmAction = (action: () => Promise<void>, message: string) => {
        setConfirmAction(() => action);
        setConfirmMessage(message);
        setConfirmDialogOpen(true);
        handleActionsMenuClose();
    };

    const handleConfirmDialogClose = () => {
        setConfirmDialogOpen(false);
    };

    const handleConfirm = async () => {
        setConfirmDialogOpen(false);
        try {
            await confirmAction();
            setAlertSeverity('success');
            setAlertMessage('Action completed successfully');
        } catch (error) {
            setAlertSeverity('error');
            setAlertMessage(`Error: ${error}`);
        }
        setAlertOpen(true);
    };

    const handleAlertClose = () => {
        setAlertOpen(false);
    };

    const clearThreads = async () => {
        await api.clearThreads();
    };

    const registerCommands = async () => {
        await api.registerCommands();
    };

    const reloadUsers = async () => {
        await api.reloadUsers();
    };

    const quitBot = async () => {
        await api.quit();
    };

    const ITEM_HEIGHT = '300px';
    const databaseItems = [
        { label: 'Chat Commands', path: '/chat_commands' },
        { label: 'Discord Messages', path: '/discord_messages' },
        { label: 'User Feedback', path: '/user_feedback' },
    ];

    const menuItems = [
        {label: 'Configure', path: '/config'},
        {label: 'Users', path: '/users'},
    ];

    const actionItems = [
        {
            label: 'Clear Threads',
            action: () => handleConfirmAction(
                clearThreads,
                "Are you sure you want to clear all threads?"
            )
        },
        {
            label: 'Register Discord Commands',
            action: () => handleConfirmAction(
                registerCommands,
                "Are you sure you want to register Discord slash commands?"
            )
        },
        {label: 'Reload Users', action: () => handleConfirmAction(
            reloadUsers,
                "Are you sure you want to reload the user cache?"
            )},
        {
            label: 'Kill Bot',
            action: () => handleConfirmAction(quitBot, "Are you sure you want to quit the bot?")
        },
    ];

    return (
        <Box>
            <AppBar position="fixed" sx={{zIndex: theme.zIndex.drawer + 1}}>
                <Toolbar>
                    <Box component="img"
                         sx={{width: 40, height: 40, mr: 1}}
                         src={disconcierge_icon}
                    />

                        <Link
                            underline="none"
                            component="h1"
                            variant="h6"
                            color="inherit"
                            noWrap
                            sx={{flexGrow: 1, cursor: 'pointer' }}
                            onClick={() => handleNavigation("/")}
                        >DisConcierge
                        </Link>

                    {isAuthenticated && (
                        isMobile ? (
                            <>
                                <IconButton
                                    size="large"
                                    edge="start"
                                    color="inherit"
                                    aria-label="menu"
                                    onClick={handleMenuOpen}
                                >
                                    <MenuIcon />
                                </IconButton>
                                <Menu
                                    anchorEl={anchorEl}
                                    open={Boolean(anchorEl)}
                                    onClose={handleMenuClose}
                                    slotProps={{
                                        paper: {
                                            style: {
                                                maxHeight: ITEM_HEIGHT,
                                                width: '20ch',
                                            },
                                        },
                                    }}
                                >
                                    {menuItems.map((item) => (
                                        <MenuItem key={item.path}
                                                  onClick={() => handleNavigation(item.path)}>
                                            {item.label}
                                        </MenuItem>
                                    ))}
                                    <Divider />
                                    <MenuItem>
                                        <Typography variant="subtitle1"
                                                    fontWeight="bold">Actions</Typography>
                                    </MenuItem>
                                    {actionItems.map((item) => (
                                        <MenuItem key={item.label} onClick={item.action}>
                                            {item.label}
                                        </MenuItem>
                                    ))}
                                    <Divider />
                                    <MenuItem>
                                        <Typography variant="subtitle1"
                                                    fontWeight="bold">Database</Typography>
                                    </MenuItem>
                                    {databaseItems.map((item) => (
                                        <MenuItem key={item.path}
                                                  onClick={() => handleNavigation(item.path)}>
                                            {item.label}
                                        </MenuItem>
                                    ))}
                                    <Divider />
                                    <MenuItem onClick={logout}>Log out</MenuItem>
                                </Menu>
                            </>
                        ) : (
                            <>
                                {menuItems.map((item) => (
                                    <Button
                                        key={item.path}
                                        color="inherit"
                                        onClick={() => handleNavigation(item.path)}
                                    >
                                        {item.label}
                                    </Button>
                                ))}

                                <Button
                                    color="inherit"
                                    onClick={handleActionsMenuOpen}
                                    endIcon={<KeyboardArrowDownIcon />}
                                >
                                    Actions
                                </Button>
                                <Menu
                                    anchorEl={actionsAnchorEl}
                                    open={Boolean(actionsAnchorEl)}
                                    onClose={handleActionsMenuClose}
                                >
                                    {actionItems.map((item) => (
                                        <MenuItem key={item.label} onClick={item.action}>
                                            {item.label}
                                        </MenuItem>
                                    ))}
                                </Menu>

                                <Button
                                    color="inherit"
                                    onClick={handleDatabaseMenuOpen}
                                    endIcon={<KeyboardArrowDownIcon />}
                                >
                                    Database
                                </Button>
                                <Menu
                                    anchorEl={databaseAnchorEl}
                                    open={Boolean(databaseAnchorEl)}
                                    onClose={handleDatabaseMenuClose}
                                >
                                    {databaseItems.map((item) => (
                                        <MenuItem key={item.path} onClick={() => handleNavigation(item.path)}>
                                            {item.label}
                                        </MenuItem>
                                    ))}
                                </Menu>

                                <Button color="inherit" onClick={logout}>Log out</Button>
                            </>

                        )
                    )}

                    <Menu
                        anchorEl={actionsAnchorEl}
                        open={Boolean(actionsAnchorEl)}
                        onClose={handleActionsMenuClose}
                    >
                        {actionItems.map((item) => (
                            <MenuItem key={item.label} onClick={item.action}>
                                {item.label}
                            </MenuItem>
                        ))}
                    </Menu>


                    {isAuthenticated ? (
<></>
                    ) : (
                        !location.pathname.includes('/login') && (
                            <Button color="inherit" onClick={() => history('/login')}>Log
                                In</Button>
                        )
                    )}
                </Toolbar>
            </AppBar>

            <Dialog
                open={confirmDialogOpen}
                onClose={handleConfirmDialogClose}
                aria-labelledby="alert-dialog-title"
                aria-describedby="alert-dialog-description"
            >
                <DialogTitle id="alert-dialog-title">{"Confirmation"}</DialogTitle>
                <DialogContent>
                    <DialogContentText id="alert-dialog-description">
                        {confirmMessage}
                    </DialogContentText>
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleConfirmDialogClose}>Cancel</Button>
                    <Button onClick={handleConfirm} autoFocus>Confirm</Button>
                </DialogActions>
            </Dialog>
            <Snackbar open={alertOpen} autoHideDuration={6000} onClose={handleAlertClose}>
                <Alert onClose={handleAlertClose} severity={alertSeverity} sx={{width: '100%'}}>
                    {alertMessage}
                </Alert>
            </Snackbar>

        </Box>
    );
};

export default AppMenu;