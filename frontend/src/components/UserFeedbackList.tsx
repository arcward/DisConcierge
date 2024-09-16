import React, {useCallback, useEffect, useState} from 'react';
import {
    Box,
    Button,
    CircularProgress,
    Dialog,
    DialogActions,
    DialogContent,
    DialogTitle,
    Link,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Typography,
}                                                from '@mui/material';
import {UserFeedbackResponse}                    from '../models/UserFeedback';
import api                                       from '../api/apiClient';
import ChatCommandDetail                               from '../models/ChatCommandDetail';
import {useNavigate} from "react-router-dom";

const UserFeedbackList: React.FC = () => {
    const history = useNavigate();
    const [userFeedbackResponse, setUserFeedbackResponse] = useState<UserFeedbackResponse | null>(
        null);
    const [loading, setLoading] = useState(true);
    const [offset, setOffset] = useState(0);

    const [selectedChatCommand, setSelectedChatCommand] = useState<ChatCommandDetail | null>(null);
    const [dialogOpen, setDialogOpen] = useState(false);

    const LIMIT = 25;

    const handleCloseDialog = () => {
        setDialogOpen(false);
        setSelectedChatCommand(null);
    };

    const fetchUserFeedback = useCallback(async (isLoadingMore: boolean = false) => {
        if (!isLoadingMore) {
            setLoading(true);
        }
        try {
            const response = await api.getUserFeedback('desc', LIMIT, offset);
            setUserFeedbackResponse(prevResponse => {
                if (prevResponse && isLoadingMore) {
                    return new UserFeedbackResponse({
                        ...response,
                        feedback: [...prevResponse.feedback, ...response.feedback],
                    });
                }
                return response;
            });
            setLoading(false);
        } catch (error) {
            console.error('Error fetching user feedback:', error);
            setLoading(false);
        }
    }, [offset]);

    useEffect(() => {
        fetchUserFeedback().then(r => console.log(r));
    }, [fetchUserFeedback]);

    const handleLoadMore = useCallback(() => {
        setOffset(prevOffset => prevOffset + LIMIT);
    }, []);

    useEffect(() => {
        if (offset > 0) {
            fetchUserFeedback(true);
        }
    }, [offset, fetchUserFeedback]);

    if (loading && !userFeedbackResponse) {
        return <Typography>Loading...</Typography>;
    }

    if (!userFeedbackResponse) {
        return <Typography>No feedback data available.</Typography>;
    }

    return (
        <Box>
            <Typography variant="h4" gutterBottom>User Feedback</Typography>
            <TableContainer component={Paper}>
                <Table>
                    <TableHead>
                        <TableRow>
                            <TableCell>ID</TableCell>
                            <TableCell>Chat Command ID</TableCell>
                            <TableCell>User ID</TableCell>
                            <TableCell>Type</TableCell>
                            <TableCell>Description</TableCell>
                            <TableCell>Created At</TableCell>
                        </TableRow>
                    </TableHead>
                    <TableBody>
                        {userFeedbackResponse.feedback.map((feedback) => (
                            <TableRow key={feedback.id}>
                                <TableCell><Link
                                    component="button"
                                    variant="body2"
                                    onClick={() => history(`/user_feedback/${feedback.id}`)}
                                >{feedback.id}
                                </Link></TableCell>
                                <TableCell>
                                    <Link
                                        component="button"
                                        variant="body2"
                                        onClick={() => history(`/chat_command/${feedback.chat_command_id}`)}
                                    >
                                        {feedback.chat_command_id}
                                    </Link>
                                </TableCell>
                                <TableCell>{feedback.user_id}</TableCell>
                                <TableCell>{feedback.type}</TableCell>
                                <TableCell>{feedback.description}</TableCell>
                                <TableCell>{new Date(feedback.created_at).toLocaleString()}</TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>
            </TableContainer>

            {userFeedbackResponse.hasNextPage() && (
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

            <Typography variant="body2" sx={{mt: 2}}>
                Showing {userFeedbackResponse.feedback.length} of {userFeedbackResponse.total} total
                feedback entries
            </Typography>
            <Typography variant="body2">
                Page {userFeedbackResponse.getCurrentPage()} of {userFeedbackResponse.getTotalPages()}
            </Typography>

            <Dialog open={dialogOpen} onClose={handleCloseDialog} maxWidth="md" fullWidth>
                <DialogTitle>Chat Command Details</DialogTitle>
                <DialogContent>
                    {selectedChatCommand && (
                        <Box>
                            <Typography variant="body1"><strong>ID:</strong> {selectedChatCommand.chat_command.id}
                            </Typography>
                            <Typography variant="body1"><strong>User
                                ID:</strong> {selectedChatCommand.chat_command.user_id}</Typography>
                            <Typography variant="body1"><strong>Username:</strong> {selectedChatCommand.chat_command.user?.username}</Typography>
                            <Typography variant="body1"><strong>Prompt:</strong> {selectedChatCommand.chat_command.prompt}
                            </Typography>
                            <Typography variant="body1"><strong>Response:</strong> {selectedChatCommand.chat_command.response}
                            </Typography>
                            <Typography variant="body1"><strong>State:</strong> {selectedChatCommand.chat_command.state}
                            </Typography>
                            {/* Add more fields as needed */}
                        </Box>
                    )}
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleCloseDialog}>Close</Button>
                </DialogActions>
            </Dialog>

        </Box>
    );
};

export default UserFeedbackList;