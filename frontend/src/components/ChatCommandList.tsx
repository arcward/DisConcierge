import React, { useCallback, useEffect, useState } from 'react';
import {
    Box,
    Button,
    CircularProgress,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    TextField,
    Tooltip,
    Typography,
} from '@mui/material';
import ChatCommand from '../models/ChatCommand';
import api from '../api/apiClient';

const ChatCommandsList: React.FC = () => {
    const [chatCommands, setChatCommands] = useState<ChatCommand[]>([]);
    const [loading, setLoading] = useState(true);
    const [offset, setOffset] = useState(0);
    const [hasMore, setHasMore] = useState(true);
    const [openModal, setOpenModal] = useState(false);
    const [selectedCommand, setSelectedCommand] = useState<ChatCommand | null>(null);

    const LIMIT = 25; // Number of items to fetch per request

    const fetchChatCommands = useCallback(async (isLoadingMore: boolean = false) => {
        if (!isLoadingMore) {
            setLoading(true);
        }
        try {
            const response = await api.getChatCommands('desc', LIMIT, offset);
            if (response.length < LIMIT) {
                setHasMore(false);
            }
            setChatCommands(prevCommands => isLoadingMore ? [...prevCommands, ...response] : response);
            setLoading(false);
        } catch (error) {
            console.error('Error fetching chat commands:', error);
            setLoading(false);
        }
    }, [offset]);

    useEffect(() => {
        fetchChatCommands();
    }, [fetchChatCommands]);

    const handleLoadMore = () => {
        setOffset(prevOffset => prevOffset + LIMIT);
        fetchChatCommands(true);
    };

    const handleOpenModal = (command: ChatCommand) => {
        setSelectedCommand(command);
        setOpenModal(true);
    };

    const handleCloseModal = () => {
        setOpenModal(false);
        setSelectedCommand(null);
    };

    const truncateText = (text: string | null | undefined, maxLength: number) => {
        if (!text) {
            return 'N/A';
        }
        return text.length > maxLength ? `${text.substring(0, maxLength)}...` : text;
    };

    if (loading && chatCommands.length === 0) {
        return <Typography>Loading...</Typography>;
    }

    return (
        <Box>
            <Typography variant="h4" gutterBottom>Chat Commands</Typography>
            <TableContainer component={Paper}>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>ID</TableCell>
                            <TableCell>Username</TableCell>
                            <TableCell>Prompt</TableCell>
                            <TableCell>Response</TableCell>
                            <TableCell>State</TableCell>
                            <TableCell>Actions</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {chatCommands.map((command) => (
                            <TableRow key={command.id} sx={{height: '60px'}}>
                                <TableCell>{command.id}</TableCell>
                                <TableCell>{command.user?.username || 'N/A'}</TableCell>
                                <TableCell>
                                    <Tooltip title={command.prompt} arrow>
                                        <span>{truncateText(command.prompt, 50)}</span>
                                    </Tooltip>
                                </TableCell>
                                <TableCell>
                                    <Tooltip title={command.response || 'N/A'} arrow>
                                        <span>{truncateText(command.response, 50)}</span>
                                    </Tooltip>
                                </TableCell>
                                <TableCell>{command.state}</TableCell>
                                <TableCell>
                                    <Button variant="outlined" onClick={() => handleOpenModal(command)}>
                                        View Details
                                    </Button>
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>

            {hasMore && (
                <Box sx={{display: 'flex', justifyContent: 'center', mt: 2}}>
                    <Button
                        variant="contained"
                        onClick={handleLoadMore}
                        disabled={loading}
                    >
                        {loading ? <CircularProgress size={24}/> : 'Load More'}
                    </Button>
                </Box>
            )}

            <Dialog open={openModal} onClose={handleCloseModal} maxWidth="md" fullWidth>
                <DialogTitle>Chat Command Details</DialogTitle>
                <DialogContent>
                    {selectedCommand && (
                        <Box>
                            <TextField
                                label="Content"
                                multiline
                                fullWidth
                                InputProps={{
                                    readOnly: true,
                                    style: { height: '100px', overflowY: 'auto' }
                                }}
                                value={selectedCommand.content || 'N/A'}
                                margin="normal"
                                variant="outlined"
                            />
                            <TextField
                                label="Prompt"
                                multiline
                                fullWidth
                                InputProps={{
                                    readOnly: true,
                                    style: { height: '100px', overflowY: 'auto' }
                                }}
                                value={selectedCommand.prompt || 'N/A'}
                                margin="normal"
                                variant="outlined"
                            />
                            <TextField
                                label="Response"
                                multiline
                                fullWidth
                                InputProps={{
                                    readOnly: true,
                                    style: { height: '100px', overflowY: 'auto' }
                                }}
                                value={selectedCommand.response || 'N/A'}
                                margin="normal"
                                variant="outlined"
                            />
                            <TextField
                                label="User"
                                multiline
                                fullWidth
                                InputProps={{
                                    readOnly: true,
                                    style: { height: '100px', overflowY: 'auto' }
                                }}
                                value={JSON.stringify(selectedCommand.user, null, 2) || 'N/A'}
                                margin="normal"
                                variant="outlined"
                            />
                            {Object.entries(selectedCommand).map(([key, value]) => {
                                if (!['content', 'prompt', 'response', 'user'].includes(key)) {
                                    return (
                                        <Typography key={key} variant="body1" gutterBottom>
                                            <strong>{key}:</strong> {JSON.stringify(value)}
                                        </Typography>
                                    );
                                }
                                return null;
                            })}
                        </Box>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleCloseModal}>Close</Button>
                </DialogActions>
            </Dialog>
        </Box>
    );
};

export default ChatCommandsList;