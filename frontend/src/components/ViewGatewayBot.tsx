import React, {useEffect, useState} from 'react';
import Typography from '@mui/material/Typography';
import GatewayBot from '../models/GatewayBot';
import {useSnackbar} from "../alertLoadingContext";
import api                          from '../api/apiClient';
import Skeleton from "@mui/material/Skeleton";
import InfoIcon from '@mui/icons-material/Info';
import Box                          from "@mui/material/Box";

const ViewGatewayBot = () => {

    const {showSnackbar} = useSnackbar();
    const [loading, setLoading] = useState<boolean>(true);
    const [gatewayBot, setGatewayBot] = useState<GatewayBot | null>(null);
    useEffect(() => {
        const fetchGatewayBot = async () => {
            try {
                const gb = await api.getGatewayBot()
                setGatewayBot(gb);
                setLoading(false);
            } catch (error) {
                showSnackbar(`Error fetching gateway bot: ${error}`, "error");
                setLoading(false);
            }
        }
        fetchGatewayBot()
    }, [showSnackbar])

    if (loading) {
        return <div><Skeleton variant="rectangular" width={210} height={118}/></div>;
    }

    return (
        <div>
            <Box sx={{display: 'flex', alignItems: 'center', mb: 2}}>
            <InfoIcon/>
            <Typography variant="h6" component="h1" sx={{ml: 1}}>
                Gateway Bot
            </Typography>
            </Box>
            <Typography variant="body1" gutterBottom>
                <strong>Shards:</strong> {gatewayBot?.shards}
            </Typography>
            <Typography variant="body1" gutterBottom>
                <strong>Session Start Limit:</strong> {gatewayBot?.session_start_limit.total}
            </Typography>
            <Typography variant="body1" gutterBottom>
                <strong>Session Remaining:</strong> {gatewayBot?.session_start_limit.remaining}
            </Typography>
            <Typography variant="body1" gutterBottom>
                <strong>Session Reset After:</strong> {gatewayBot?.session_start_limit.reset_after}
            </Typography>
        </div>
    )
}

export default ViewGatewayBot;