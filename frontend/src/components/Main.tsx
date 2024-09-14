import React                                        from 'react';
import {Box, Button, Grid, Icon, Paper, Typography} from '@mui/material';
import {Link as RouterLink}                         from 'react-router-dom';
import SettingsIcon                           from '@mui/icons-material/Settings';
import PeopleIcon                             from '@mui/icons-material/People';

import ChatIcon                               from '@mui/icons-material/Chat';
import AlternateEmailIcon                     from '@mui/icons-material/AlternateEmail';
import FeedbackIcon from '@mui/icons-material/Feedback';
import ViewGatewayBot from './ViewGatewayBot';


const MainPage = () => {
    const pages = [
        {
            title: 'Configure',
            description: 'Adjust bot settings and configurations',
            link: '/config',
            icon: SettingsIcon
        },
        {
            title: 'Users',
            description: 'Manage and view Discord user information',
            link: '/users',
            icon: PeopleIcon
        },
        {
            title: 'User Feedback',
            description: 'User feedback to /chat and /private commands',
            link: '/user_feedback',
            icon: FeedbackIcon
        },
        {
            title: 'Chat Commands',
            description: 'View and analyze chat interactions',
            link: '/chat_commands',
            icon: ChatIcon
        },
        {
            title: 'Discord Messages',
            description: 'Monitor Discord message activity',
            link: '/discord_messages',
            icon: AlternateEmailIcon
        },

    ];

    return (
        <Box sx={{flexGrow: 1, padding: 3}}>
            <Typography variant="h3" gutterBottom>
                Welcome to DisConcierge Admin
            </Typography>
            <Typography variant="h5" gutterBottom>
                Your Discord Bot Management Dashboard
            </Typography>
            <Box sx={{my: 4}}>
                <Typography variant="body1" paragraph>
                    DisConcierge is your OpenAI-powered Discord bot.
                </Typography>
                <Typography variant="body1" paragraph>
                    Use this admin interface to manage users, configure commands, view interactions,
                    and fine-tune your bot's behavior.
                </Typography>
            </Box>
            <Grid container spacing={3}>
                {pages.map((page) => (
                    <Grid item xs={12} sm={6} md={4} key={page.title}>
                        <Paper elevation={3}
                               sx={{
                                   p: 3,
                                   height: '100%',
                                   display: 'flex',
                                   flexDirection: 'column'
                               }}>
                            <Box sx={{display: 'flex', alignItems: 'center', mb: 2}}>
                                <Icon  component={page.icon}></Icon>
                                <Typography variant="h6" sx={{ml: 1}}>
                                  {page.title}
                                </Typography>
                            </Box>
                            <Typography variant="body2" sx={{flex: 1}}>
                                {page.description}
                            </Typography>
                            <Button
                                component={RouterLink}
                                to={page.link}
                                variant="contained"
                                color="primary"
                                sx={{mt: 2}}
                            >
                                Go to {page.title}
                            </Button>
                        </Paper>
                    </Grid>
                ))}
                <Grid item xs={12} sm={6} md={4}>
                    <Paper elevation={3}   sx={{
                        p: 3,
                        height: '100%',
                        display: 'flex',
                        flexDirection: 'column'
                    }}>

                            <ViewGatewayBot/>

                    </Paper>

                </Grid>
            </Grid>
        </Box>
    );
};

export default MainPage;