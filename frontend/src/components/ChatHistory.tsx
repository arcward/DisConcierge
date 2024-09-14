import React             from 'react';
import UserHistoryModel  from '../models/UserHistoryModel';
import {Box, Typography} from '@mui/material';

const UserHistoryView = ({history}: { history: UserHistoryModel[] }) => (
    <Box>
        {history.map((item, index) => (
            <Box key={index} mb={2}>
                <Typography variant="subtitle1" component="div">
                    <strong>Prompt:</strong> {item.prompt}
                </Typography>
                <Typography variant="body1" component="div">
                    <strong>Response:</strong> {item.response || 'N/A'}
                </Typography>
                {item.error && (
                    <Typography variant="body2" color="error">
                        <strong>Error:</strong> {item.error}
                    </Typography>
                )}
                <Typography variant="caption" color="textSecondary">
                    <strong>Created At:</strong> {new Date(item.created_at).toLocaleString()}
                </Typography>
                {/*<Divider sx={{ my: 1 }} />*/}
                <Typography variant="body2" component="div">
                    <strong>State</strong>: {item.state} <br/>
                    <strong>Step:</strong> {item.step} <br/>
                    <strong>Run Status:</strong> {item.run_status} <br/>
                    <strong>Run ID:</strong> {item.run_id} <br/>
                    <strong>Thread ID:</strong> {item.thread_id} <br/>
                    <strong>Interaction ID:</strong> {item.interaction_id} <br/>
                    <strong>Context:</strong> {item.context} <br/>
                    <strong>Whisper:</strong> {item.private ? 'Yes' : 'No'} <br/>
                    <strong>Feedback:</strong> {item.feedback}
                </Typography>
            </Box>
        ))}
    </Box>

);

export default UserHistoryView;
