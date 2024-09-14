import React                from 'react';
import {
    Button,
    Checkbox,
    FormControl,
    FormControlLabel,
    Grid,
    InputLabel,
    MenuItem,
    Select,
    Slider,
    TextField
}                           from '@mui/material';
import UserModel            from '../models/User';
import {TruncationStrategy} from '../models/RuntimeConfigModel';
import {SelectChangeEvent}  from "@mui/material/Select";
import Typography           from "@mui/material/Typography";

interface UserEditProps {
    user: UserModel;
    editedValues: Partial<UserModel>;
    modifiedFields: Set<keyof UserModel>;
    onInputChange: (event:
                        React.ChangeEvent<HTMLInputElement
                            | HTMLTextAreaElement>
                        | SelectChangeEvent<unknown>
                        | { target: { name: string; value: number | string | boolean } },
                    field: keyof UserModel) => void;
    onSave: () => void;
    onCancel: () => void;
}

const UserEdit: React.FC<UserEditProps> = ({
                                               user,
                                               editedValues,
                                               modifiedFields,
                                               onInputChange,
                                               onSave,
                                               onCancel
                                           }) => {
    const isFieldModified = (field: keyof UserModel) => modifiedFields.has(field);
    const getFieldStyle = (field: keyof UserModel) => ({
        '& .MuiOutlinedInput-root': {
            '& fieldset': {
                borderColor: isFieldModified(field) ? 'orange' : 'inherit',
            },
            '&:hover fieldset': {
                borderColor: isFieldModified(field) ? 'orange' : 'inherit',
            },
            '&.Mui-focused fieldset': {
                borderColor: isFieldModified(field) ? 'orange' : 'primary.main',
            },
        },
        '& .MuiCheckbox-root': {
            color: isFieldModified(field) ? 'orange' : 'inherit',
        },
        '& .MuiSlider-thumb': {
            color: isFieldModified(field) ? 'orange' : 'primary.main',
        },
        '& .MuiSlider-track': {
            color: isFieldModified(field) ? 'orange' : 'primary.main',
        },
        '& .MuiSlider-rail': {
            color: isFieldModified(field) ? 'orange' : 'primary.main',
        },
    });


    return (
        <Grid container spacing={2}>
            <Grid item xs={12}>
                <TextField
                    fullWidth
                    label="Username"
                    value={user.username}
                    disabled
                />
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth
                    label="Global Name"
                    value={user.global_name}
                    disabled
                />
            </Grid>
            <Grid item xs={12}>
                <FormControlLabel
                    control={
                        <Checkbox
                            checked={editedValues.priority ?? user.priority}
                            onChange={(e) => onInputChange(e, 'priority')}
                            sx={getFieldStyle('priority')}
                        />
                    }
                    label="Priority"
                />
            </Grid>
            <Grid item xs={12}>
                <FormControlLabel
                    control={
                        <Checkbox
                            checked={editedValues.ignored ?? user.ignored}
                            onChange={(e) => onInputChange(e, 'ignored')}
                            sx={getFieldStyle('ignored')}
                        />
                    }
                    label="Ignored"
                />
            </Grid>

            <Grid item xs={6}>
                <TextField
                    fullWidth
                    type="number"
                    label="/chat Limit (6h)"
                    inputProps={{step: 1, min: 1}}
                    value={editedValues.user_chat_command_limit_6h !== undefined ? editedValues.user_chat_command_limit_6h : user.user_chat_command_limit_6h || 0}
                    onChange={(e) => onInputChange(e, 'user_chat_command_limit_6h')}
                    sx={getFieldStyle('user_chat_command_limit_6h')}
                />
            </Grid>
            <Grid item xs={12}>
                <FormControl fullWidth>
                    <InputLabel>Truncation Strategy</InputLabel>
                    <Select
                        value={editedValues.openai_truncation_strategy_type ?? user.openai_truncation_strategy_type ?? ''}
                        onChange={(e: SelectChangeEvent) => onInputChange(
                            e,
                            'openai_truncation_strategy_type'
                        )}
                        label="Truncation Strategy"
                        sx={getFieldStyle('openai_truncation_strategy_type')}
                    >
                        <MenuItem value={TruncationStrategy.Auto}>auto</MenuItem>
                        <MenuItem value={TruncationStrategy.LastMessages}>last_messages</MenuItem>
                    </Select>
                </FormControl>
            </Grid>
            <Grid item xs={6}>
                <TextField
                    fullWidth
                    type="number"
                    label="Max Completion Tokens"
                    inputProps={{step: 1, min: 0}}
                    value={editedValues.openai_max_completion_tokens !== undefined ? editedValues.openai_max_completion_tokens : user.openai_max_completion_tokens || 0}
                    onChange={(e) => onInputChange(e, 'openai_max_completion_tokens')}
                    sx={getFieldStyle('openai_max_completion_tokens')}
                />
            </Grid>
            <Grid item xs={6}>
                <TextField
                    fullWidth
                    type="number"
                    label="Max Prompt Tokens"
                    value={editedValues.openai_max_prompt_tokens !== undefined ? editedValues.openai_max_prompt_tokens : user.openai_max_prompt_tokens || 0}
                    onChange={(e) => onInputChange(e, 'openai_max_prompt_tokens')}
                    sx={getFieldStyle('openai_max_prompt_tokens')}
                />
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth
                    type="number"
                    label="Truncation Strategy Last Messages"
                    inputProps={{step: 1, min: 1}}
                    value={editedValues.openai_truncation_strategy_last_messages !== undefined ? editedValues.openai_truncation_strategy_last_messages : user.openai_truncation_strategy_last_messages || 0}
                    onChange={(e) => onInputChange(e, 'openai_truncation_strategy_last_messages')}
                    sx={getFieldStyle('openai_truncation_strategy_last_messages')}
                />
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth
                    multiline
                    rows={4}
                    label="Assistant Instructions"
                    value={editedValues.assistant_instructions !== undefined ? editedValues.assistant_instructions : user.assistant_instructions || ''}
                    onChange={(e) => onInputChange(e, 'assistant_instructions')}
                    sx={getFieldStyle('assistant_instructions')}
                />
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth
                    multiline
                    rows={4}
                    label="Assistant Additional Instructions"
                    value={editedValues.assistant_additional_instructions !== undefined ? editedValues.assistant_additional_instructions : user.assistant_additional_instructions || ''}
                    onChange={(e) => onInputChange(e, 'assistant_additional_instructions')}
                    sx={getFieldStyle('assistant_additional_instructions')}
                />
            </Grid>
            <Grid item xs={6}>
                <Typography id="assistant-temperature-slider" gutterBottom>
                    Assistant Temperature
                </Typography>
                <Slider
                    aria-labelledby="assistant-temperature-slider"
                    valueLabelDisplay="auto"
                    step={0.1}
                    marks
                    min={0}
                    max={2}
                    value={
                        typeof editedValues.assistant_temperature === 'number'
                            ? editedValues.assistant_temperature
                            : typeof user.assistant_temperature === 'number'
                                ? user.assistant_temperature
                                : 0
                    }
                    onChange={(event: Event, newValue: number | number[]) => {
                        const value = Array.isArray(newValue) ? newValue[0] : newValue;
                        onInputChange(
                            {target: {name: 'assistant_temperature', value}},
                            'assistant_temperature'
                        );
                    }}
                    sx={getFieldStyle('assistant_temperature')}
                />
            </Grid>
            <Grid item xs={6}>
                <TextField
                    fullWidth
                    type="string"
                    label="Assistant Poll Interval"
                    value={editedValues.assistant_poll_interval !== undefined ? editedValues.assistant_poll_interval : user.assistant_poll_interval || ''}
                    onChange={(e) => onInputChange(e, 'assistant_poll_interval')}
                    sx={getFieldStyle('assistant_poll_interval')}
                />
            </Grid>
            <Grid item xs={12}>
                <TextField
                    fullWidth
                    type="string"
                    label="Assistant Max Poll Interval"
                    value={editedValues.assistant_max_poll_interval !== undefined ? editedValues.assistant_max_poll_interval : user.assistant_max_poll_interval || ''}
                    onChange={(e) => onInputChange(e, 'assistant_max_poll_interval')}
                    sx={getFieldStyle('assistant_max_poll_interval')}
                />
            </Grid>
            <Grid item xs={12}>
                <Button onClick={onSave}
                        variant="contained"
                        color="primary"
                        style={{marginRight: '10px'}}>
                    Save
                </Button>
                <Button onClick={onCancel} variant="outlined">
                    Cancel
                </Button>
            </Grid>
        </Grid>
    );
};

export default UserEdit;