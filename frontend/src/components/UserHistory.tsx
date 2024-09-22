import React, {ReactElement, useEffect, useState} from 'react';
import apiClient                                  from '../api/apiClient';
import {List, ListItem}                           from "@mui/material";
import Box                                        from "@mui/material/Box";
import UserModel                                  from '../models/User';
import UserHistoryModel                           from '../models/UserHistoryModel';


function renderMessage(msg: UserHistoryModel): ReactElement {
    console.log('msg', msg);
    return (
        <List>
            <ListItem>{msg.prompt}</ListItem>
            <ListItem><strong>{msg.response}</strong></ListItem>
        </List>
    )
}

const UserHistoryList = (props: UserModel) => {
    const [userHistory, setUserHistory] = useState<UserHistoryModel[]>([]);
    const [loading, setLoading] = useState(true);
    const [alertOpen, setAlertOpen] = React.useState(false);
    const [alertSeverity, setAlertSeverity] = React.useState('info');
    const [alertMsg, setAlertMsg] = useState('');


    const setAlertError = (msg: string) => {
        setAlertSeverity('error');
        setAlertMsg(msg);
        setAlertOpen(true);
    };

    useEffect(() => {
        const fetchUserHistory = async () => {
            if (!props.id) {
                setLoading(false);
                return;
            }
            try {
                setUserHistory(await apiClient.getUserHistory(props.id));
                setLoading(false);
            } catch (error: any) {
                setAlertError(`Error fetching status: ${error.response.status}: ${JSON.stringify(
                    error.response.data,
                    null,
                    2
                )}`);
                setLoading(false);
            }
        };
        fetchUserHistory();
    }, []);

    return (
        <Box>
            <Box>
                <List>
                    {userHistory.map((msg, index) => (
                        <ListItem key={index}>
                            {renderMessage(msg)}
                        </ListItem>

                    ))}
                </List>
            </Box>
        </Box>
    );
}

export default UserHistoryList;