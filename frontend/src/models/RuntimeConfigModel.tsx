export enum TruncationStrategy {
    // You'll need to define the actual values here based on your openai.TruncationStrategy
    Auto = "auto",
    LastMessages = "last_messages",
    // Add other strategies as needed
}

export enum DBLogLevel {
    DEBUG = "DEBUG",
    INFO = "INFO",
    WARN = "WARN",
    ERROR = "ERROR"
}

class RuntimeConfigModel {
    id: number;
    created_at: number;
    updated_at: number;
    deleted_at: number | null;

    paused: boolean;
    recover_panic: boolean;

    discord_gateway_enabled: boolean;
    discord_custom_status: string;
    discord_error_message: string;
    discord_rate_limit_message: string;
    discord_notification_channel_id: string;

    feedback_enabled: boolean;
    feedback_modal_input_label: string;
    feedback_modal_placeholder: string;
    feedback_modal_min_length: number;
    feedback_modal_max_length: number;
    feedback_modal_title: string;

    chat_command_max_attempts: number;
    chat_command_description: string;
    chat_command_option_description: string;
    chat_command_min_length: number;
    chat_command_max_length: number;

    private_command_description: string;
    private_command_option_description: string;

    openai_truncation_strategy_type: TruncationStrategy;
    openai_truncation_strategy_last_messages: number;
    openai_max_requests_per_second: number;
    openai_max_prompt_tokens: number;
    openai_completion_tokens: number;

    assistant_poll_interval: string;
    assistant_max_poll_interval: string;
    assistant_instructions: string;
    assistant_additional_instructions: string;
    assistant_temperature: number;

    user_chat_command_limit_6h: number;


    log_level: DBLogLevel;
    openai_log_level: DBLogLevel;
    discord_log_level: DBLogLevel;
    discordgo_log_level: DBLogLevel;
    database_log_level: DBLogLevel;
    discord_webhook_log_level: DBLogLevel;
    api_log_level: DBLogLevel;

    constructor(data: Partial<RuntimeConfigModel>) {
        this.id = data.id!;
        this.created_at = data.created_at!;
        this.updated_at = data.updated_at!;
        this.deleted_at = data.deleted_at!;

        this.paused = data.paused!;
        this.recover_panic = data.recover_panic!;
        this.chat_command_max_attempts = data.chat_command_max_attempts!;
        this.discord_custom_status = data.discord_custom_status!;
        this.discord_error_message = data.discord_error_message!;
        this.discord_rate_limit_message = data.discord_rate_limit_message!;
        this.discord_gateway_enabled = data.discord_gateway_enabled!;
        this.discord_notification_channel_id = data.discord_notification_channel_id!;
        this.feedback_enabled = data.feedback_enabled!;
        this.feedback_modal_input_label = data.feedback_modal_input_label!;
        this.feedback_modal_placeholder = data.feedback_modal_placeholder!;
        this.feedback_modal_min_length = data.feedback_modal_min_length!;
        this.feedback_modal_max_length = data.feedback_modal_max_length!;
        this.feedback_modal_title = data.feedback_modal_title!;

        this.chat_command_description = data.chat_command_description!;
        this.chat_command_option_description = data.chat_command_option_description!;
        this.chat_command_min_length = data.chat_command_min_length!;
        this.chat_command_max_length = data.chat_command_max_length!;

        this.private_command_description = data.private_command_description!;
        this.private_command_option_description = data.private_command_option_description!;

        this.openai_truncation_strategy_type = data.openai_truncation_strategy_type!;
        this.openai_truncation_strategy_last_messages = data.openai_truncation_strategy_last_messages!;
        this.openai_max_requests_per_second = data.openai_max_requests_per_second!;
        this.openai_max_prompt_tokens = data.openai_max_prompt_tokens!;
        this.openai_completion_tokens = data.openai_completion_tokens!;

        this.assistant_poll_interval = data.assistant_poll_interval!;
        this.assistant_max_poll_interval = data.assistant_max_poll_interval!;
        this.assistant_instructions = data.assistant_instructions!;
        this.assistant_temperature = data.assistant_temperature!;
        this.assistant_additional_instructions = data.assistant_additional_instructions!;

        this.user_chat_command_limit_6h = data.user_chat_command_limit_6h!;
        this.log_level = data.log_level!;
        this.openai_log_level = data.openai_log_level!;
        this.discord_log_level = data.discord_log_level!;
        this.discordgo_log_level = data.discordgo_log_level!;
        this.database_log_level = data.database_log_level!;
        this.discord_webhook_log_level = data.discord_webhook_log_level!;
        this.api_log_level = data.api_log_level!;
    }
}

export interface RuntimeConfigUpdate {
    discord_custom_status?: string;
    recover_panic?: boolean;
    discord_gateway_enabled?: boolean;
    discord_rate_limit_message?: string;
    discord_error_message?: string;
    discord_notification_channel_id?: string;
    feedback_enabled?: boolean;
    feedback_modal_input_label?: string;
    feedback_modal_placeholder?: string;
    feedback_modal_min_length?: number;
    feedback_modal_max_length?: number;
    feedback_modal_title?: string;
    chat_command_description?: string;

    chat_command_option_description?: string;
    chat_command_min_length?: number;
    chat_command_max_length?: number;
    private_command_description?: string;
    private_command_option_description?: string;
    openai_truncation_strategy_type?: TruncationStrategy;
    openai_truncation_strategy_last_messages?: number;
    openai_max_requests_per_second?: number;
    openai_max_prompt_tokens?: number;
    openai_max_completion_tokens?: number;
    assistant_poll_interval?: string;
    assistant_max_poll_interval?: string;
    assistant_instructions?: string;
    assistant_additional_instructions?: string;
    paused?: boolean;
    assistant_temperature?: number;
    chat_command_max_attempts?: number;
    user_chat_command_limit_6h?: number;
    log_level?: DBLogLevel;
    openai_log_level?: DBLogLevel;
    discord_log_level?: DBLogLevel;
    discordgo_log_level?: DBLogLevel;
    database_log_level?: DBLogLevel;
    discord_webhook_log_level?: DBLogLevel;
    api_log_level?: DBLogLevel;
}


export default RuntimeConfigModel;