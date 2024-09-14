import React, {useEffect, useState} from 'react';
import RuntimeConfigModel, {
    RuntimeConfigUpdate,
    TruncationStrategy
}                                   from '../models/RuntimeConfigModel';
import Skeleton                     from '@mui/material/Skeleton';
import Box                          from '@mui/material/Box';
import Typography                   from "@mui/material/Typography";
import api                          from '../api/apiClient';
import TextField                    from '@mui/material/TextField';
import Button                       from '@mui/material/Button';
import Select                       from '@mui/material/Select';
import Tooltip                      from '@mui/material/Tooltip';
import MenuItem                     from '@mui/material/MenuItem';
import {
    AppBar,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    FormControl,
    FormControlLabel,
    Grid,
    InputLabel,
    Paper,
    SelectChangeEvent,
    Slider,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Toolbar
}                                   from "@mui/material";
import {useSnackbar}                from '../alertLoadingContext';
import Switch                       from "@mui/material/Switch";

const RuntimeConfigView = () => {
    const {showSnackbar} = useSnackbar();
    const [runtimeConfig, setRuntimeConfig] = useState<RuntimeConfigModel | null>(null);
    const [loading, setLoading] = useState<boolean>(true);
    const [error, setError] = useState<any>(null);
    const [formData, setFormData] = useState<RuntimeConfigUpdate>({});
    const [changedFields, setChangedFields] = useState<Set<string>>(new Set());
    const [originalFormData, setOriginalFormData] = useState<RuntimeConfigUpdate>({});
    const [confirmDialogOpen, setConfirmDialogOpen] = useState(false);

    useEffect(() => {
        const fetchStatus = async () => {
            try {
                const stateData = await api.getConfig()
                setRuntimeConfig(stateData);
                setFormData(stateData);
                setOriginalFormData(stateData);
                setLoading(false);

            } catch (error) {
                console.log('error: ', JSON.stringify(error, null, 2));
                showSnackbar(`error: ${JSON.stringify(error, null, 2)}`, 'error');
                // setAlertError(`Error getting bot state config: ${error}`);
                setLoading(false);
            }
        };

        fetchStatus();
    }, [showSnackbar]);


    const getChangedFieldsData = () => {
        return Array.from(changedFields).map(field => ({
            field,
            oldValue: originalFormData[field as keyof RuntimeConfigUpdate],
            newValue: formData[field as keyof RuntimeConfigUpdate]
        }));
    };

    const handleInputChange = (event: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const {name, value, type} = event.target;
        setFormData(prevState => ({
            ...prevState, [name]: type === 'number' ? Number(value) : value
        }));
        if (value !== runtimeConfig?.[name as keyof RuntimeConfigModel]) {
            setChangedFields(prev => new Set(prev).add(name));
        } else {
            setChangedFields(prev => {
                const newSet = new Set(prev);
                newSet.delete(name);
                return newSet;
            });
        }
    };

    const handleOnSelectChange = (event: SelectChangeEvent<unknown>) => {
        const {name, value} = event.target;
        setFormData(prevState => ({
            ...prevState, [name as string]: value
        }));
        if (value !== runtimeConfig?.[name as keyof RuntimeConfigModel]) {
            setChangedFields(prev => new Set(prev).add(name as string));
        } else {
            setChangedFields(prev => {
                const newSet = new Set(prev);
                newSet.delete(name as string);
                return newSet;
            });
        }
    };

    const handleSwitchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const {name, checked} = event.target;
        setFormData(prevState => ({
            ...prevState,
            [name]: checked
        }));
        if (checked !== runtimeConfig?.[name as keyof RuntimeConfigModel]) {
            setChangedFields(prev => new Set(prev).add(name));
        } else {
            setChangedFields(prev => {
                const newSet = new Set(prev);
                newSet.delete(name);
                return newSet;
            });
        }
    };

    const handleSubmit = (event: React.FormEvent) => {
        event.preventDefault();
        setConfirmDialogOpen(true);
    };

    const handleConfirmSubmit = async () => {
        setConfirmDialogOpen(false);
        const changedFieldsObject = Object.fromEntries(
            Array.from(changedFields).map(key => [key, formData[key as keyof RuntimeConfigUpdate]])
        );

        try {
            const updatedState = await api.updateBotState(changedFieldsObject);
            setRuntimeConfig(updatedState);
            setFormData(updatedState);
            setOriginalFormData(updatedState);
            setChangedFields(new Set());
            setError(null);
            // setAlertSuccess(`Updated config`);
            showSnackbar('Updated config', 'success');
        } catch (error) {
            console.error('Failed to update bot state:', error);
            showSnackbar(`Failed to update bot state: ${error}`, 'error');
            // setAlertError(`Failed to update bot state: ${error}`);
        }
    };


    const handleCancelSubmit = () => {
        setConfirmDialogOpen(false);
        setFormData(originalFormData);
        setChangedFields(new Set());
    };


    if (loading) {
        return <div><Skeleton variant="rectangular" width={210} height={118}/></div>;
    }
    if (error) {
        return <div>{error}</div>;
    }

    return (<Box sx={{pb: 7, pl: 2}}>
        <Typography variant="h4">Bot Config</Typography>


        <form onSubmit={handleSubmit}>
            <Grid container>
                <Grid container item>
                    <Grid item xs={12}>
                        <Typography variant="h6">General</Typography>
                    </Grid>
                    <Grid item xs={12}>
                        <Tooltip title="If false, panics occurring during a slash command will not be caught, crashing the bot.
                         If true, panics will be logged.">
                            <FormControlLabel
                                control={
                                    <Switch
                                        checked={formData.recover_panic}
                                        onChange={handleSwitchChange}
                                        name="recover_panic"
                                    />
                                }
                                label="Recover Panic"
                            />
                        </Tooltip>
                    </Grid>
                </Grid>
                <Grid container item>
                    <Grid item xs={12}>
                        <Typography variant="h6">Discord</Typography>
                    </Grid>
                    <Grid container item spacing={1}>
                        <Grid item xs={12} md={12}>
                            <Tooltip title="If true, the bot will connect to the Discord websocket gateway.
                            If false, the bot will not connect, and will disconnect if already connected.">
                                <FormControlLabel
                                    control={
                                        <Switch
                                            checked={formData.discord_gateway_enabled}
                                            onChange={handleSwitchChange}
                                            name="discord_gateway_enabled"
                                        />
                                    }
                                    label="Gateway Connection"
                                />
                            </Tooltip>
                        </Grid>

                        <Box width="100%"/>

                        <Grid item xs={12} md={3}>
                            <Tooltip title="If set (and the gateway connection is enabled), the bot will attempt to send event notifications to the given channel ID (new user seen, errors, feedback, users reaching their rate limit, ...)">
                                <TextField
                                    fullWidth
                                    margin="dense"
                                    name="discord_notification_channel_id"
                                    label="Notification Channel ID"
                                    value={formData.discord_notification_channel_id || ''}
                                    onChange={handleInputChange}
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: changedFields.has(
                                                    "discord_notification_channel_id") ? 'orange' : 'inherit',
                                            },
                                        },
                                    }}
                                />
                            </Tooltip>
                        </Grid>

                        <Box width="100%"/>

                        <Grid item xs={12} md={6}>
                            <Tooltip title="Sets the Discord bot's status. Only takes effect when the gateway connection is enabled."
                                     placement="top-start">
                                <TextField
                                    fullWidth
                                    margin="dense"
                                    name="discord_custom_status"
                                    label="Custom Status"
                                    value={formData.discord_custom_status || ''}
                                    onChange={handleInputChange}
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: changedFields.has(
                                                    "discord_custom_status") ? 'orange' : 'inherit',
                                            },
                                        },
                                    }}
                                />
                            </Tooltip>
                        </Grid>

                        <Box width="100%"/>

                        <Grid item xs={12} md={6}>
                            <Tooltip title="Response returned to the user if they try to use a command while they already have one in progress. If not set, the 'thinking...' message will just be deleted with no explanation to the user.">
                                <TextField
                                    fullWidth
                                    margin="dense"
                                    name="discord_rate_limit_message"
                                    label="Rate Limit Message"
                                    value={formData.discord_rate_limit_message || ''}
                                    onChange={handleInputChange}
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: changedFields.has(
                                                    "discord_rate_limit_message") ? 'orange' : 'inherit',
                                            },
                                        },
                                    }}
                                />
                            </Tooltip>
                        </Grid>

                        <Box width="100%"/>
                        <Grid item xs={12} md={6}>
                            <Tooltip title="Message returned to the user if an error occurs and their command can't be completed">
                                <TextField
                                    fullWidth
                                    margin="dense"
                                    name="discord_error_message"
                                    label="Error Message"
                                    value={formData.discord_error_message || ''}
                                    onChange={handleInputChange}
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: changedFields.has(
                                                    "discord_error_message") ? 'orange' : 'inherit',
                                            },
                                        },
                                    }}
                                />
                            </Tooltip>
                        </Grid>
                    </Grid>

                </Grid>

                <Grid container spacing={1}>
                    <Grid item xs={12}>
                        <Typography variant="h6">Discord User Feedback</Typography>
                    </Grid>


                    <Grid item xs={12} md={12}>
                        <Tooltip title="If enabled, /chat and /private command responses will have Discord button components attached (Good, Outdated, Inaccurate, Other). If disabled, only the response text will be shown.">
                            <FormControlLabel
                                control={
                                    <Switch
                                        checked={formData.feedback_enabled}
                                        onChange={handleSwitchChange}
                                        name="feedback_enabled"
                                    />
                                }
                                label="Enabled"
                            />
                        </Tooltip>
                    </Grid>


                    <Grid item xs={6} md={1}>
                        <Tooltip title="Minimum user input length when using the 'Other' feedback button">
                            <TextField

                                margin="dense"
                                type="number"
                                name="feedback_modal_min_length"
                                label="Modal Min Length"
                                value={formData.feedback_modal_min_length || ''}
                                onChange={handleInputChange}
                                sx={{
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: changedFields.has(
                                                "feedback_modal_min_length") ? 'orange' : 'inherit',
                                        },
                                    },
                                }}
                            />
                        </Tooltip>
                    </Grid>
                    <Grid item xs={6} md={1}>
                        <Tooltip title="Maximum user input length when using the 'Other' feedback button">
                            <TextField
                                margin="dense"
                                type="number"
                                name="feedback_modal_max_length"
                                label="Modal Max Length"
                                value={formData.feedback_modal_max_length || ''}
                                onChange={handleInputChange}
                                sx={{
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: changedFields.has(
                                                "feedback_modal_max_length") ? 'orange' : 'inherit',
                                        },
                                    },
                                }}
                            />
                        </Tooltip>
                    </Grid>
                    <Grid item xs={12}>

                        <Grid item xs={12} md={6}>
                            <Tooltip title="Input label to display on the text modal for the 'Other' button">
                                <TextField
                                    fullWidth
                                    margin="dense"
                                    name="feedback_modal_input_label"
                                    label="Modal Input Label"
                                    value={formData.feedback_modal_input_label || ''}
                                    onChange={handleInputChange}
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: changedFields.has(
                                                    "feedback_modal_input_label") ? 'orange' : 'inherit',
                                            },
                                        },
                                    }}
                                />
                            </Tooltip>
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <Tooltip title="Placeholder text to display in the 'Other' modal input text field">
                                <TextField
                                    fullWidth
                                    margin="dense"
                                    name="feedback_modal_placeholder"
                                    label="Modal Placeholder"
                                    value={formData.feedback_modal_placeholder || ''}
                                    onChange={handleInputChange}
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: changedFields.has(
                                                    "feedback_modal_placeholder") ? 'orange' : 'inherit',
                                            },
                                        },
                                    }}
                                />
                            </Tooltip>
                        </Grid>
                        <Grid item xs={12} md={6}>
                            <Tooltip title="Title to display in the 'Other' modal input text field">
                                <TextField
                                    fullWidth
                                    margin="dense"
                                    name="feedback_modal_title"
                                    label="Modal Title"
                                    value={formData.feedback_modal_title || ''}
                                    onChange={handleInputChange}
                                    sx={{
                                        '& .MuiOutlinedInput-root': {
                                            '& fieldset': {
                                                borderColor: changedFields.has(
                                                    "feedback_modal_title") ? 'orange' : 'inherit',
                                            },
                                        },
                                    }}
                                />
                            </Tooltip>
                        </Grid>
                    </Grid>
                </Grid>
                <Grid container spacing={1}>
                    <Grid item xs={12}>
                        <Typography variant="h6">OpenAI</Typography>
                    </Grid>

                    <Grid item xs={12} md={3}>

                        <Typography id="assistant-temperature-slider" gutterBottom>
                            Assistant Temperature
                        </Typography>
                        <Tooltip title="Overrides the assistant's configured temperature. Higher values make the output more random, while lower values make it more focused/deterministic">
                        <Slider
                            aria-labelledby="assistant-temperature-slider"
                            valueLabelDisplay="auto"
                            step={0.1}
                            marks
                            min={0}
                            max={2}
                            value={formData.assistant_temperature || 0}
                            onChange={(_event: Event, newValue: number | number[]) => {
                                const value = Array.isArray(newValue) ? newValue[0] : newValue;
                                setFormData(prevState => ({
                                    ...prevState,
                                    assistant_temperature: value
                                }));
                                if (value !== runtimeConfig?.assistant_temperature) {
                                    setChangedFields(prev => new Set(prev).add(
                                        'assistant_temperature'));
                                } else {
                                    setChangedFields(prev => {
                                        const newSet = new Set(prev);
                                        newSet.delete('assistant_temperature');
                                        return newSet;
                                    });
                                }
                            }}
                            sx={{
                                '& .MuiSlider-thumb': {
                                    color: changedFields.has('assistant_temperature') ? 'orange' : 'primary.main',
                                },
                                '& .MuiSlider-track': {
                                    color: changedFields.has('assistant_temperature') ? 'orange' : 'primary.main',
                                },
                                '& .MuiSlider-rail': {
                                    color: changedFields.has('assistant_temperature') ? 'orange' : 'primary.main',
                                },
                            }}
                        />
                        </Tooltip>
                    </Grid>

                    <Box width="100%"/>

                    <Grid item xs={12} md={2}>
                        <Tooltip title="Maximum number of 'Create Run' OpenAI API requests permitted, per second">
                        <TextField
                            fullWidth
                            margin="dense"
                            type="number"
                            name="openai_max_requests_per_second"
                            label="Max 'Create Run' Requests/sec"
                            value={formData.openai_max_requests_per_second || ''}
                            onChange={handleInputChange}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: changedFields.has(
                                            "openai_max_requests_per_second") ? 'orange' : 'inherit',
                                    },
                                },
                            }}
                        />
                        </Tooltip>
                    </Grid>

                    <Box width="100%"/>

                    <Grid item xs={6} md={2}>
                        <TextField
                            fullWidth
                            margin="dense"
                            type="number"
                            name="openai_max_prompt_tokens"
                            label="Max Prompt Tokens"
                            value={formData.openai_max_prompt_tokens || ''}
                            onChange={handleInputChange}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: changedFields.has("openai_max_prompt_tokens") ? 'orange' : 'inherit',
                                    },
                                },
                            }}
                        />
                    </Grid>
                    <Grid item xs={6} md={2}>
                        <TextField
                            fullWidth
                            margin="dense"
                            type="number"
                            name="openai_max_completion_tokens"
                            label="Max Completion Tokens"
                            value={formData.openai_max_completion_tokens || ''}
                            onChange={handleInputChange}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: changedFields.has(
                                            "openai_max_completion_tokens") ? 'orange' : 'inherit',
                                    },
                                },
                            }}
                        />
                    </Grid>

                    <Box width="100%"/>

                    <Grid item xs={6} md={3}>
                        <FormControl
                            fullWidth
                            margin="dense"
                        >
                            <InputLabel
                                margin="dense"
                            >Truncation Strategy</InputLabel>
                            <Select
                                margin="dense"
                                name="openai_truncation_strategy_type"
                                value={formData.openai_truncation_strategy_type || ''}
                                onChange={handleOnSelectChange}
                                label="openai_truncation_strategy_type"
                                sx={{
                                    '& .MuiOutlinedInput-notchedOutline': {
                                        borderColor: changedFields.has(
                                            "openai_truncation_strategy_type") ? 'orange' : 'inherit',
                                    },
                                }}
                            >
                                <MenuItem value={TruncationStrategy.Auto}>auto</MenuItem>
                                <MenuItem
                                    value={TruncationStrategy.LastMessages}>last_messages</MenuItem>
                            </Select>
                        </FormControl>
                    </Grid>
                    <Grid item xs={4} md={2}>
                        <TextField
                            fullWidth
                            margin="dense"
                            type="number"
                            name="openai_truncation_strategy_last_messages"
                            label="Last Messages"
                            value={formData.openai_truncation_strategy_last_messages || ''}
                            disabled={formData.openai_truncation_strategy_type === TruncationStrategy.Auto}
                            onChange={handleInputChange}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: changedFields.has(
                                            "openai_truncation_strategy_last_messages") ? 'orange' : 'inherit',
                                    },
                                },
                            }}
                        />
                    </Grid>

                    <Box width="100%"/>
                    <Grid item xs={6} md="auto">
                        <Tooltip title="Default delay between checking for an updated OpenAI run status">
                            <TextField
                                fullWidth
                                margin="dense"
                                type="string"
                                name="assistant_poll_interval"
                                label="Assistant poll interval"
                                value={formData.assistant_poll_interval || ''}
                                onChange={handleInputChange}
                                sx={{
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: changedFields.has(
                                                "assistant_poll_interval") ? 'orange' : 'inherit',
                                        },
                                    },
                                }}
                            />
                        </Tooltip>
                    </Grid>
                    <Grid item xs={6} md="auto">
                        <Tooltip title="Maximum back-off delay when checking the OpenAI run status">
                            <TextField
                                fullWidth
                                margin="dense"
                                type="string"
                                name="assistant_max_poll_interval"
                                label="Assistant max poll interval"
                                value={formData.assistant_max_poll_interval || ''}
                                onChange={handleInputChange}
                                sx={{
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: changedFields.has(
                                                "assistant_max_poll_interval") ? 'orange' : 'inherit',
                                        },
                                    },
                                }}
                            />
                        </Tooltip>
                    </Grid>

                    <Box width="100%"/>

                    <Grid item xs={12} md={6}>
                        <Tooltip title="Instructions to the OpenAI Assistant. Overrides instructions set in the playground.">
                            <TextField
                                fullWidth
                                rows={4}
                                multiline
                                margin="dense"
                                name="assistant_instructions"
                                label="Instructions"
                                value={formData.assistant_instructions || ''}
                                onChange={handleInputChange}
                                sx={{
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: changedFields.has("assistant_instructions") ? 'orange' : 'inherit',
                                        },
                                    },
                                }}
                            />
                        </Tooltip>
                    </Grid>

                    <Box width="100%"/>

                    <Grid item xs={12} md={6}>
                        <TextField
                            fullWidth
                            rows={4}
                            multiline
                            margin="dense"
                            name="assistant_additional_instructions"
                            label="Additional Instructions"
                            value={formData.assistant_additional_instructions || ''}
                            onChange={handleInputChange}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: changedFields.has(
                                            "assistant_additional_instructions") ? 'orange' : 'inherit',
                                    },
                                },
                            }}
                        />
                    </Grid>
                </Grid>


                <Grid container>
                    <Grid item xs={12}>
                        <Typography variant="h6">Chat Commands</Typography>
                    </Grid>
                    <Grid item xs={12} md={2}>
                        <Tooltip title="Maximum number of attempts to execute a /chat or /private command. This primarily applies to scenarios where the bot crashes during execution of a command (the bot normally will not retry failures)">
                            <TextField
                                fullWidth
                                margin="dense"
                                type="number"
                                name="chat_command_max_attempts"
                                label="Max Attempts"
                                value={formData.chat_command_max_attempts || ''}
                                onChange={handleInputChange}
                                sx={{
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: changedFields.has(
                                                "chat_command_max_attempts") ? 'orange' : 'inherit',
                                        },
                                    },
                                }}
                            />
                        </Tooltip>
                    </Grid>
                    <Grid item xs={12} md={2}>
                        <Tooltip title="Number of /chat and /private commands a user is permitted to use over a period of 6 hours. Only applies to commands that incur token usage. Changing this value will only update users that currently have the default set.">
                            <TextField
                                fullWidth
                                margin="dense"
                                type="number"
                                name="user_chat_command_limit_6h"
                                label="User /chat and /private limit (per 6 hours)"
                                value={formData.user_chat_command_limit_6h || ''}
                                onChange={handleInputChange}
                                sx={{
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: changedFields.has(
                                                "user_chat_command_limit_6h") ? 'orange' : 'inherit',
                                        },
                                    },
                                }}
                            />
                        </Tooltip>
                    </Grid>


                    <Grid item xs={12} md={2}>
                        <Tooltip title="Sets the maximum length on /chat (and /private) command inputs. Register Discord commands again for this to take effect.">
                            <TextField
                                fullWidth
                                margin="dense"
                                type="number"
                                name="chat_command_max_length"
                                label="Max Prompt Length"
                                value={formData.chat_command_max_length || ''}
                                onChange={handleInputChange}
                                sx={{
                                    '& .MuiOutlinedInput-root': {
                                        '& fieldset': {
                                            borderColor: changedFields.has("chat_command_max_length") ? 'orange' : 'inherit',
                                        },
                                    },
                                }}
                            />
                        </Tooltip>
                    </Grid>
                </Grid>
                <Box width="100%"/>
                <Grid item xs={12} md={6}>
                    <Tooltip title="Sets the description of the /chat command. Register Discord commands again for this to take effect.">
                        <TextField
                            fullWidth
                            margin="dense"
                            name="chat_command_description"
                            label="Command Description"
                            value={formData.chat_command_description || ''}
                            onChange={handleInputChange}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: changedFields.has("chat_command_description") ? 'orange' : 'inherit',
                                    },
                                },
                            }}
                        />
                    </Tooltip>
                </Grid>
                <Box width="100%"/>
                <Grid item xs={12} md={6}>
                    <Tooltip title="Sets the option description for the /chat and /private command prompt input. Register Discord commands again for this to take effect.">
                        <TextField
                            fullWidth
                            margin="dense"
                            name="chat_command_option_description"
                            label="Option Description"
                            value={formData.chat_command_option_description || ''}
                            onChange={handleInputChange}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: changedFields.has(
                                            "chat_command_option_description") ? 'orange' : 'inherit',
                                    },
                                },
                            }}
                        />
                    </Tooltip>
                </Grid>
                <Box width="100%"/>
                <Grid item xs={12} md={6}>
                    <Tooltip title="Sets the description of the /private command. Register Discord commands again for this to take effect.">
                        <TextField
                            fullWidth
                            margin="dense"
                            name="private_command_description"
                            label="Private Command Description"
                            value={formData.private_command_description || ''}
                            onChange={handleInputChange}
                            sx={{
                                '& .MuiOutlinedInput-root': {
                                    '& fieldset': {
                                        borderColor: changedFields.has(
                                            "private_command_description") ? 'orange' : 'inherit',
                                    },
                                },
                            }}
                        />
                    </Tooltip>
                </Grid>


                <Box width="100%"/>
                <Grid container md={6}>
                    <Grid item xs={12}>
                        <Typography variant="h6">Logging</Typography>
                    </Grid>

                    <Grid container spacing={1}>
                        {['log_level', 'openai_log_level', 'discord_log_level', 'discordgo_log_level', 'database_log_level', 'discord_webhook_log_level', 'api_log_level'].map(
                            (level) => (
                                <Grid item xs={4} sm={3} md={3} key={level}>
                                    <FormControl fullWidth>
                                        <InputLabel>{level.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(
                                            1)).join(' ')}</InputLabel>
                                        <Select
                                            fullWidth
                                            size="small"
                                            margin="dense"
                                            name={level}
                                            value={formData[level as keyof RuntimeConfigUpdate] || ''}
                                            onChange={handleOnSelectChange}
                                            label={level.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(
                                                1)).join(' ')}
                                            sx={{
                                                '& .MuiOutlinedInput-notchedOutline': {
                                                    borderColor: changedFields.has(level) ? 'orange' : 'inherit',
                                                },
                                            }}
                                        >
                                            <MenuItem value="DEBUG">DEBUG</MenuItem>
                                            <MenuItem value="INFO">INFO</MenuItem>
                                            <MenuItem value="WARN">WARN</MenuItem>
                                            <MenuItem value="ERROR">ERROR</MenuItem>
                                        </Select>
                                    </FormControl>
                                </Grid>))}
                    </Grid>
                </Grid>
            </Grid>

        </form>

        <AppBar
            position="fixed"
            color="primary"
            sx={{top: 'auto', bottom: 0, backgroundColor: 'background.paper'}}
        >
            <Toolbar>
                <Button
                    type="submit"
                    variant="contained"
                    color="primary"
                    onClick={handleSubmit}
                    disabled={changedFields.size === 0}
                >
                    Save Changes
                </Button>
            </Toolbar>
        </AppBar>


        <Dialog
            open={confirmDialogOpen}
            onClose={handleCancelSubmit}
            aria-labelledby="alert-dialog-title"
            aria-describedby="alert-dialog-description"
            maxWidth="md"
            fullWidth
        >
            <DialogTitle id="alert-dialog-title">{"Confirm Changes"}</DialogTitle>
            <DialogContent>
                <DialogContentText id="alert-dialog-description">
                    Are you sure you want to save these changes?
                </DialogContentText>
                <TableContainer component={Paper} sx={{marginTop: 2}}>
                    <Table>
                        <TableHead>
                            <TableRow>
                                <TableCell>Field</TableCell>
                                <TableCell>Current Value</TableCell>
                                <TableCell>New Value</TableCell>
                            </TableRow>
                        </TableHead>
                        <TableBody>
                            {getChangedFieldsData().map(({field, oldValue, newValue}) => (
                                <TableRow key={field}>
                                    <TableCell>{field}</TableCell>
                                    <TableCell>{oldValue?.toString() ?? 'N/A'}</TableCell>
                                    <TableCell>{newValue?.toString() ?? 'N/A'}</TableCell>
                                </TableRow>
                            ))}
                        </TableBody>
                    </Table>
                </TableContainer>
            </DialogContent>
            <DialogActions>
                <Button onClick={handleCancelSubmit} color="primary">
                    Cancel
                </Button>
                <Button onClick={handleConfirmSubmit} color="primary" autoFocus>
                    Confirm
                </Button>
            </DialogActions>
        </Dialog>
    </Box>);
};

export default RuntimeConfigView;
