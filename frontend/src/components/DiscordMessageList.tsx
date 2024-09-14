import React, {useCallback, useEffect, useState} from 'react';
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
    Tooltip,
    Typography,
}                                                from '@mui/material';
import DiscordMessage                            from '../models/DiscordMessage';
import api                                       from '../api/apiClient';

const DiscordMessageList: React.FC = () => {
    const [discordMessages, setDiscordMessages] = useState<DiscordMessage[]>([]);
    const [loading, setLoading] = useState(true);
    const [offset, setOffset] = useState(0);
    const [hasMore, setHasMore] = useState(true);
    const [openModal, setOpenModal] = useState(false);
    const [selectedMessage, setSelectedMessage] = useState<DiscordMessage | null>(null);

    const LIMIT = 25; // Number of items to fetch per request

    const fetchDiscordMessages = useCallback(async (isLoadingMore: boolean = false) => {
        if (!isLoadingMore) {
            setLoading(true);
        }
        try {
            const response = await api.getDiscordMessages('desc', LIMIT, offset);
            if (response.length < LIMIT) {
                setHasMore(false);
            }
            setDiscordMessages(prevCommands => isLoadingMore ? [...prevCommands, ...response] : response);
            setLoading(false);
        } catch (error) {
            console.error('Error fetching chat commands:', error);
            setLoading(false);
        }
    }, [offset]);

    useEffect(() => {
        fetchDiscordMessages();
    }, [fetchDiscordMessages]);

    const handleLoadMore = () => {
        setOffset(prevOffset => prevOffset + LIMIT);
        fetchDiscordMessages(true);
    };

    const handleOpenModal = (command: DiscordMessage) => {
        setSelectedMessage(command);
        setOpenModal(true);
    };

    const handleCloseModal = () => {
        setOpenModal(false);
        setSelectedMessage(null);
    };

    const truncateText = (text: string | null | undefined, maxLength: number) => {
        if (!text) {
            return 'N/A';
        }
        return text.length > maxLength ? `${text.substring(0, maxLength)}...` : text;
    };

    if (loading && discordMessages.length === 0) {
        return <Typography>Loading...</Typography>;
    }

    return (
        <Box>
            <Typography variant="h4" gutterBottom>Discord Messages</Typography>
            <TableContainer component={Paper}>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>ID</TableCell>
                            <TableCell>Username</TableCell>
                            <TableCell>ChannelID</TableCell>
                            <TableCell>InteractionID</TableCell>
                            <TableCell>Content</TableCell>
                            <TableCell>Actions</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {discordMessages.map((command) => (
                            <TableRow key={command.id} sx={{height: '60px'}}>
                                <TableCell>{command.id}</TableCell>
                                <TableCell>{command.username}</TableCell>
                                <TableCell>{command.channel_id}</TableCell>

                                <TableCell>{command.interaction_id}</TableCell>
                                <TableCell>
                                    <Tooltip title={command.content} arrow>
                                        <span>{truncateText(command.content, 50)}</span>
                                    </Tooltip>
                                </TableCell>
                                <TableCell>
                                    <Button variant="outlined"
                                            onClick={() => handleOpenModal(command)}>
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
                <DialogTitle>Message Details</DialogTitle>
                <DialogContent>
                    {selectedMessage && (
                        <Box>
                            {Object.entries(selectedMessage).map(([key, value]) => (
                                <Typography key={key} variant="body1" gutterBottom>
                                    <strong>{key}:</strong> {JSON.stringify(value)}
                                </Typography>
                            ))}
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

export default DiscordMessageList;