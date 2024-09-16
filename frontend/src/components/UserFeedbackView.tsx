import React, {useEffect, useState} from 'react';
import {useParams}                  from 'react-router-dom';
import {
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
import {UserFeedback}               from '../models/UserFeedback';
import api                          from '../api/apiClient';
import {useSnackbar}                from '../alertLoadingContext';

const UserFeedbackView: React.FC = () => {
    const {id} = useParams<{ id: string }>();
    const [feedback, setFeedback] = useState<UserFeedback | null>(null);
    const [loading, setLoading] = useState(true);
    const {showSnackbar} = useSnackbar();

    useEffect(() => {
        const fetchFeedback = async () => {
            try {
                if (!id) {
                    throw new Error('No feedback ID provided');
                }
                const response = await api.getUserFeedbackByID(parseInt(id, 10));
                setFeedback(new UserFeedback(response));
            } catch (error) {
                console.error('Error fetching user feedback:', error);
                showSnackbar(`Error fetching user feedback: ${error}`, 'error');
            } finally {
                setLoading(false);
            }
        };

        fetchFeedback();
    }, [id, showSnackbar]);

    if (loading) {
        return <CircularProgress/>;
    }

    if (!feedback) {
        return <Typography>No feedback found</Typography>;
    }

    return (
        <Box>
            <Typography variant="h4" gutterBottom>User Feedback Details</Typography>
            <Paper elevation={3}>
                <TableContainer>
                    <Table>
                        <TableBody>
                            <TableRow>
                                <TableCell><strong>ID</strong></TableCell>
                                <TableCell>{feedback.id}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>Chat Command ID</strong></TableCell>
                                <TableCell>{feedback.chat_command_id}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>User ID</strong></TableCell>
                                <TableCell>{feedback.user_id}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>Type</strong></TableCell>
                                <TableCell>{feedback.type}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>Description</strong></TableCell>
                                <TableCell>{feedback.description}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>Detail</strong></TableCell>
                                <TableCell>{feedback.detail}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>Created At</strong></TableCell>
                                <TableCell>{feedback.getCreatedAtDate().toLocaleString()}</TableCell>
                            </TableRow>
                            <TableRow>
                                <TableCell><strong>Updated At</strong></TableCell>
                                <TableCell>{feedback.getUpdatedAtDate().toLocaleString()}</TableCell>
                            </TableRow>
                        </TableBody>
                    </Table>
                </TableContainer>
            </Paper>
        </Box>
    );
};

export default UserFeedbackView;