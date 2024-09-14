import React, {useEffect, useState} from 'react';
import Table                        from '@mui/material/Table';
import TableBody                    from '@mui/material/TableBody';
import TableCell                    from '@mui/material/TableCell';
import TableContainer               from '@mui/material/TableContainer';
import TablePagination              from '@mui/material/TablePagination';
import TableHead                    from '@mui/material/TableHead';
import TableRow                     from '@mui/material/TableRow';
import Paper                        from '@mui/material/Paper';
import api                          from '../api/apiClient';
import Button                       from "@mui/material/Button";
import Checkbox                     from '@mui/material/Checkbox';
import {
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    Snackbar
}                                   from "@mui/material";
import Alert, {
    AlertColor
}                                   from "@mui/material/Alert";
import Box                          from "@mui/material/Box";
import UserHistoryView              from './ChatHistory';
import UserHistoryModel             from '../models/UserHistoryModel';
import UserModel                    from "../models/User";
import TextField                    from "@mui/material/TextField";
import {
    TruncationStrategy
}                                   from "../models/RuntimeConfigModel";
import {
    SelectChangeEvent
}                                   from "@mui/material/Select";
import UserEdit                     from './UserEdit';

const Users = () => {
    const [modalOpen, setModalOpen] = useState<boolean>(false);
    const [users, setUsers] = useState<UserModel[]>([]);
    const [loading, setLoading] = useState<boolean>(true);
    const [alertOpen, setAlertOpen] = React.useState(false);
    const [alertSeverity, setAlertSeverity] = React.useState('info');
    const [alertMsg, setAlertMsg] = useState('');
    const [modalUser, setModalUser] = useState<UserModel | null>(null);
    const [userHistory, setUserHistory] = useState<UserHistoryModel[]>([]);
    const [editModalOpen, setEditModalOpen] = useState(false);
    const [editingUser, setEditingUser] = useState<string | null>(null);
    const [editedValues, setEditedValues] = useState<Partial<UserModel>>({});

    const [page, setPage] = useState(0);
    const [rowsPerPage, setRowsPerPage] = useState(25);
    const [totalUsers, setTotalUsers] = useState(0);
    const [order, setOrder] = useState<'asc' | 'desc'>('asc');

    const [modifiedFields, setModifiedFields] = useState<Set<keyof UserModel>>(new Set());

    const handleModalClose = () => setModalOpen(false);
    const handleModalOpen = () => setModalOpen(true);

    const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);
    const [userToSave, setUserToSave] = useState<UserModel | null>(null);

    const handleConfirmSave = async () => {
        if (!userToSave) {
            return;
        }

        try {
            const updatedFields = Object.fromEntries(
                Array.from(modifiedFields).map(field => [field, editedValues[field]])
            );
            await api.updateUser(userToSave.id, updatedFields);

            setUsers((prevUsers: UserModel[]) => prevUsers.map(u => u.id === userToSave.id ? {...u, ...updatedFields} : u));
            setEditingUser(null);
            setEditedValues({});
            setModifiedFields(new Set());
            setAlertSuccess(`Updated user ${userToSave.id}`);
            setEditModalOpen(false);
            setConfirmDialogOpen(false);
            setUserToSave(null);
        } catch (error) {
            console.error('Error updating user:', error);
            setAlertError(JSON.stringify(error, null, 2));
        }
    };

    const handleCancel = () => {
        setEditingUser(null);
        setEditedValues({});
    };


    const handleEdit = (user: UserModel) => {
        setEditingUser(user.id);
        setEditedValues({
            priority: user.priority,
            ignored: user.ignored,
            user_chat_command_limit_6h: user.user_chat_command_limit_6h,
            openai_max_completion_tokens: user.openai_max_completion_tokens,
            openai_max_prompt_tokens: user.openai_max_prompt_tokens,
            openai_truncation_strategy_type: user.openai_truncation_strategy_type,
            openai_truncation_strategy_last_messages: user.openai_truncation_strategy_last_messages,
            assistant_additional_instructions: user.assistant_additional_instructions,
            assistant_temperature: user.assistant_temperature,
            assistant_poll_interval: user.assistant_poll_interval,
            assistant_max_poll_interval: user.assistant_max_poll_interval,
        });
        setModifiedFields(new Set());
        setEditModalOpen(true);
    };


    const handleCancelEdit = () => {
        setEditingUser(null);
        setEditedValues({});
        setModifiedFields(new Set());
        setEditModalOpen(false);
    };

    const handleSave = (user: UserModel) => {
        setUserToSave(user);
        setConfirmDialogOpen(true);
    };

    const handleInputChange = (
        event:
            React.ChangeEvent<HTMLInputElement
                | HTMLTextAreaElement>
            | SelectChangeEvent<unknown>
            | { target: { name: string; value: number | string | boolean } },
        field: keyof UserModel) => {
        const target = event.target;
        let value: string | number | boolean;

        if (field === 'openai_truncation_strategy_type') {
            value = event.target.value as TruncationStrategy;
        } else if (target instanceof HTMLInputElement) {
            if (target.type === 'checkbox') {
                value = target.checked;
            } else if (target.type === 'number') {
                value = target.valueAsNumber;
            } else {
                value = target.value;
            }
        } else if (typeof target.value === 'number') {
            value = target.value;
        } else {
            // This is a textarea
            value = target.value as string;
        }

        setEditedValues(prev => ({...prev, [field]: value}));
        setModifiedFields(prev => new Set(prev).add(field));
    };


    const handleClose = (event: any) => {
        setAlertOpen(false);
        setAlertMsg('');
    };

    const setAlertSuccess = (msg: string) => {
        setAlertSeverity('success');
        setAlertMsg(msg);
        setAlertOpen(true);
    };

    const setAlertError = (msg: string) => {
        setAlertSeverity('error');
        setAlertMsg(msg);
        setAlertOpen(true);
    };


    const fetchUserHistory = async (user: UserModel) => {
        try {
            const userHist = await api.getUserHistory(user.id, 'desc', 20, true);
            setUserHistory(userHist);
            setModalUser(user);
            handleModalOpen();
        } catch (error: any) {
            console.error('Error fetching user history:', error);
            setAlertError(`Error fetching user history: ${error.response.status}: ${JSON.stringify(
                error.response.data,
                null,
                2
            )}`);
        }
    };


    useEffect(() => {
        const fetchUsers = async () => {
            try {
                const response = await api.getUsers(true, order, rowsPerPage, page * rowsPerPage);
                setUsers(response);
                setTotalUsers(response.length); // This should be updated if the API returns total
                                                // count
                setLoading(false);
            } catch (error: any) {
                setAlertError(`Error fetching users: ${error.response.status}: ${JSON.stringify(
                    error.response.data,
                    null,
                    2
                )}`);
                setLoading(false);
            }
        };
        fetchUsers();
    }, [page, rowsPerPage, order]);


    const handleChangePage = (event: unknown, newPage: number) => {
        setPage(newPage);
    };

    const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
        setRowsPerPage(parseInt(event.target.value, 10));
        setPage(0);
    };

    const handleChangeOrder = () => {
        setOrder(order === 'asc' ? 'desc' : 'asc');
        setPage(0);
    };


    if (loading) {
        return <div>Loading...</div>;
    }

    return (<div>
        <h2>Users List</h2>

        <Box>
            <Snackbar open={alertOpen} onClose={handleClose}>
                <Alert
                    onClose={e => handleClose(e)}
                    severity={alertSeverity as AlertColor}
                    variant="filled"
                    sx={{width: '100%'}}
                >
                    {alertMsg}
                </Alert>
            </Snackbar>
        </Box>
        <Box>
            <Dialog
                open={modalOpen}
                onClose={handleModalClose}
                aria-labelledby="dialog-title"
                aria-describedby="dialog-description"
                maxWidth="md"
                fullWidth
            >
                <DialogTitle id="dialog-title">User History
                    for {modalUser?.global_name}</DialogTitle>
                <DialogContent dividers>
                    <DialogContentText id="dialog-description" component="div">
                        <UserHistoryView history={userHistory}/>
                    </DialogContentText>
                </DialogContent>
                <DialogActions>
                    <Button onClick={handleModalClose} color="primary">
                        Close
                    </Button>
                </DialogActions>
            </Dialog>

            <Dialog open={editModalOpen} onClose={handleCancelEdit} maxWidth="md" fullWidth>
                <DialogTitle>Edit User</DialogTitle>
                <DialogContent>
                    {editingUser && (
                        <UserEdit
                            user={users.find(u => u.id === editingUser)!}
                            editedValues={editedValues}
                            modifiedFields={modifiedFields}
                            onInputChange={handleInputChange}
                            onSave={() => handleSave(users.find(u => u.id === editingUser)!)}
                            onCancel={handleCancelEdit}
                        />

                    )}
                </DialogContent>
            </Dialog>
        </Box>

        <Dialog open={confirmDialogOpen} onClose={() => setConfirmDialogOpen(false)}>
            <DialogTitle>Confirm Changes</DialogTitle>
            <DialogContent>
                <DialogContentText>
                    Are you sure you want to save these changes?
                </DialogContentText>
            </DialogContent>
            <DialogActions>
                <Button onClick={() => setConfirmDialogOpen(false)}>Cancel</Button>
                <Button onClick={handleConfirmSave} color="primary">Confirm</Button>
            </DialogActions>
        </Dialog>

        <TableContainer component={Paper}>
            <Table>
                <TableHead>
                    <TableRow>
                        <TableCell>
                            <Button onClick={handleChangeOrder}>
                                Username {order === 'asc' ? '▲' : '▼'}
                            </Button>
                        </TableCell>
                        <TableCell>Global Name</TableCell>
                        <TableCell>User ID</TableCell>
                        <TableCell>Priority</TableCell>

                        <TableCell>Ignored</TableCell>

                        <TableCell>Billable Chat (6h)</TableCell>
                        <TableCell>Attempted Chat (6h)</TableCell>
                        <TableCell>Limit (6h)</TableCell>
                        <TableCell>Last Seen</TableCell>
                        <TableCell>Edit</TableCell>

                    </TableRow>
                </TableHead>
                <TableBody>
                    {users.map(user => (<TableRow key={user.id}>


                        <TableCell> <Button variant="text"
                                            onClick={() => fetchUserHistory(user)}>{user.username}</Button></TableCell>
                        <TableCell> {user.global_name}</TableCell>
                        <TableCell>{user.id}</TableCell>
                        <TableCell>
                            {editingUser === user.id ? (
                                <Checkbox
                                    checked={editedValues.priority ?? user.priority}
                                    onChange={(e) => handleInputChange(e, 'priority')}
                                />
                            ) : (
                                <Checkbox checked={user.priority} disabled/>

                            )}

                        </TableCell>

                        <TableCell>
                            {editingUser === user.id ? (
                                <Checkbox
                                    checked={editedValues.ignored ?? user.ignored}
                                    onChange={(e) => handleInputChange(e, 'ignored')}
                                />
                            ) : (
                                <Checkbox checked={user.ignored} disabled/>

                            )}
                        </TableCell>


                        <TableCell>{user.stats?.chat_command_usage?.billable_6h || 0}/{user.stats?.chat_command_usage?.limit_6h || 0}</TableCell>
                        <TableCell>{user.stats?.chat_command_usage?.attempted_6h || 0}</TableCell>
                        <TableCell>{editingUser === user.id ? (
                            <TextField
                                type="number"
                                value={editedValues.user_chat_command_limit_6h !== undefined ? editedValues.user_chat_command_limit_6h : user.user_chat_command_limit_6h || 0}
                                onChange={(e) => handleInputChange(
                                    e as React.ChangeEvent<HTMLInputElement>,
                                    'user_chat_command_limit_6h'
                                )}
                            />
                        ) : (
                            user.user_chat_command_limit_6h || 0
                        )}</TableCell>

                        <TableCell>{user.last_seen}</TableCell>

                        <TableCell>
                            {editingUser === user.id ? (
                                <>
                                    <Button onClick={() => handleSave(user)}>Save</Button>
                                    <Button onClick={handleCancel}>Cancel</Button>
                                </>
                            ) : (
                                <Button onClick={() => handleEdit(user)}>Edit</Button>
                            )}
                        </TableCell>

                    </TableRow>))}
                </TableBody>
            </Table>
        </TableContainer>
        <TablePagination
            rowsPerPageOptions={[25, 50, 100]}
            component="div"
            count={totalUsers}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={handleChangePage}
            onRowsPerPageChange={handleChangeRowsPerPage}
        />
    </div>);
};

export default Users;
