import React, {useEffect, useState} from 'react';
import {useParams}                  from 'react-router-dom';
import {
    Accordion,
    AccordionDetails,
    AccordionSummary,
    Box,
    CircularProgress,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableRow,
    Typography,
}                                   from '@mui/material';
import ExpandMoreIcon               from '@mui/icons-material/ExpandMore';
import ChatCommandDetail            from '../models/ChatCommandDetail';
import api                          from '../api/apiClient';
import {useSnackbar}                from '../alertLoadingContext';

const ChatCommandView: React.FC = () => {
    const {id} = useParams<{ id: string }>();
    const [chatCommand, setChatCommand] = useState<ChatCommandDetail | null>(null);
    const [loading, setLoading] = useState(true);
    const {showSnackbar} = useSnackbar();

    useEffect(() => {
        const fetchChatCommand = async () => {
            try {
                if (!id) {
                    throw new Error('No chat command ID provided');
                }
                const response = await api.getChatCommand(id);
                setChatCommand(response);
            } catch (error) {
                console.error('Error fetching chat command:', error);
                showSnackbar(`Error fetching chat command: ${error}`, 'error');
            } finally {
                setLoading(false);
            }
        };

        fetchChatCommand();
    }, [id, showSnackbar]);

    if (loading) {
        return <CircularProgress/>;
    }

    if (!chatCommand) {
        return <Typography>No chat command found</Typography>;
    }

    return (
        <Box>
            <Typography variant="h4" gutterBottom>Chat Command Details</Typography>
            <Paper elevation={3}>
                <TableContainer>
                    <Table>
                        <TableBody>
                            <TableRow>
                                <TableCell><strong>ID</strong></TableCell>
                                <TableCell>{chatCommand.chat_command.id}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>User ID</strong></TableCell>
                                <TableCell>{chatCommand.chat_command.user_id}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>Username</strong></TableCell>
                                <TableCell>{chatCommand.chat_command.user?.username}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>State</strong></TableCell>
                                <TableCell>{chatCommand.chat_command.state}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>Created At</strong></TableCell>
                                <TableCell>{new Date(chatCommand.chat_command.created_at || 0).toLocaleString()}</TableCell>
                            </TableRow>
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>

            <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                    <Typography>Prompt</Typography>
                </AccordionSummary>
                <AccordionDetails>
                    <Typography>{chatCommand.chat_command.prompt}</Typography>
                </AccordionDetails>
            </Accordion>

            <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                    <Typography>Response</Typography>
                </AccordionSummary>
                <AccordionDetails>
                    <Typography>{chatCommand.chat_command.response}</Typography>
                </AccordionDetails>
            </Accordion>

            {chatCommand.create_thread && (
                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                        <Typography>Create Thread Log</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <pre>{JSON.stringify(chatCommand.create_thread, null, 2)}</pre>
                    </AccordionDetails>
                </Accordion>
            )}

            {chatCommand.create_message && (
                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                        <Typography>Create Message Log</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <pre>{JSON.stringify(chatCommand.create_message, null, 2)}</pre>
                    </AccordionDetails>
                </Accordion>
            )}

            {chatCommand.create_run && (
                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                        <Typography>Create Run Log</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        <pre>{JSON.stringify(chatCommand.create_run, null, 2)}</pre>
                    </AccordionDetails>
                </Accordion>
            )}

            {chatCommand.retrieve_runs && chatCommand.retrieve_runs.length > 0 && (
                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                        <Typography>Retrieve Runs Log</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        {chatCommand.retrieve_runs.map((run, index) => (
                            <Accordion key={index}>
                                <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                    <Typography>Run {index + 1}</Typography>
                                </AccordionSummary>
                                <AccordionDetails>
                                    <pre>{JSON.stringify(run, null, 2)}</pre>
                                </AccordionDetails>
                            </Accordion>
                        ))}
                    </AccordionDetails>
                </Accordion>
            )}

            {chatCommand.list_messages && chatCommand.list_messages.length > 0 && (
                <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                        <Typography>List Messages Log</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                        {chatCommand.list_messages.map((message, index) => (
                            <Accordion key={index}>
                                <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                    <Typography>Message {index + 1}</Typography>
                                </AccordionSummary>
                                <AccordionDetails>
                                    <pre>{JSON.stringify(message, null, 2)}</pre>
                                </AccordionDetails>
                            </Accordion>
                        ))}
                    </AccordionDetails>
                </Accordion>
            )}
        </Box>
    );
};

export default ChatCommandView;