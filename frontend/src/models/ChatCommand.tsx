import UserModel from './User';


enum FeedbackButtonState {
    HIDDEN = 0,
    ENABLED = 1,
    DISABLED = 2
}

interface IChatCommand {
    state: string;
    step: string;
    prompt: string;
    private: boolean;
    thread_id: string;
    message_id: string;
    run_id: string;
    run_status: string;
    priority: boolean;
    attempts: number;
    usage_prompt_tokens?: number;
    usage_completion_tokens?: number;
    usage_total_tokens?: number;
    custom_id: string;

    feedback_button_state_good: FeedbackButtonState;
    feedback_button_state_outdated: FeedbackButtonState;
    feedback_button_state_hallucinated: FeedbackButtonState;
    feedback_button_state_other: FeedbackButtonState;
    feedback_button_state_reset: FeedbackButtonState;

    user_id: string;
    interaction_id: string;
    discord_message_id: string;
    token: string;
    token_expires: number;
    application_id: string;
    type: string;
    guild_id: string;
    channel_id: string;
    context: string;
    content: string;
    user: UserModel | null;
    started_at: Date | null;
    finished_at: Date | null;
    acknowledged: boolean;
    response?: string | null;
    error?: string | null;
    created_at?: number;
    updated_at?: number;
    deleted_at?: Date | null;
    id: number;
}


class ChatCommand implements IChatCommand {
    state: string;
    step: string;
    prompt: string;
    private: boolean;
    thread_id: string;
    message_id: string;
    run_id: string;
    run_status: string;
    priority: boolean;
    attempts: number;
    usage_prompt_tokens?: number;
    usage_completion_tokens?: number;
    usage_total_tokens?: number;
    custom_id: string;

    feedback_button_state_good: FeedbackButtonState;
    feedback_button_state_outdated: FeedbackButtonState;
    feedback_button_state_hallucinated: FeedbackButtonState;
    feedback_button_state_other: FeedbackButtonState;
    feedback_button_state_reset: FeedbackButtonState;

    user_id: string;
    interaction_id: string;
    discord_message_id: string;
    token: string;
    token_expires: number;
    application_id: string;
    type: string;
    guild_id: string;
    channel_id: string;
    context: string;
    content: string;
    user: UserModel | null;
    started_at: Date | null;
    finished_at: Date | null;
    acknowledged: boolean;
    response?: string | null;
    error?: string | null;
    created_at?: number;
    updated_at?: number;
    deleted_at?: Date | null;
    id: number;

    constructor(data: Partial<IChatCommand> = {}) {
        this.state = data.state ?? '';
        this.step = data.step ?? '';
        this.prompt = data.prompt ?? '';
        this.private = data.private ?? false;
        this.thread_id = data.thread_id ?? '';
        this.message_id = data.message_id ?? '';
        this.run_id = data.run_id ?? '';
        this.run_status = data.run_status ?? '';
        this.priority = data.priority ?? false;
        this.attempts = data.attempts ?? 0;
        this.usage_prompt_tokens = data.usage_prompt_tokens ?? 0;
        this.usage_completion_tokens = data.usage_completion_tokens ?? 0;
        this.usage_total_tokens = data.usage_total_tokens ?? 0;
        this.custom_id = data.custom_id ?? '';

        this.feedback_button_state_good = data.feedback_button_state_good ?? FeedbackButtonState.HIDDEN;
        this.feedback_button_state_outdated = data.feedback_button_state_outdated ?? FeedbackButtonState.HIDDEN;
        this.feedback_button_state_hallucinated = data.feedback_button_state_hallucinated ?? FeedbackButtonState.HIDDEN;
        this.feedback_button_state_other = data.feedback_button_state_other ?? FeedbackButtonState.HIDDEN;
        this.feedback_button_state_reset = data.feedback_button_state_reset ?? FeedbackButtonState.HIDDEN;

        this.user_id = data.user_id ?? '';
        this.interaction_id = data.interaction_id ?? '';
        this.discord_message_id = data.discord_message_id ?? '';
        this.token = data.token ?? '';
        this.token_expires = data.token_expires ?? 0;
        this.application_id = data.application_id ?? '';
        this.type = data.type ?? '';
        this.guild_id = data.guild_id ?? '';
        this.channel_id = data.channel_id ?? '';
        this.context = data.context ?? '';
        this.content = data.content ?? '';
        this.user = data.user ?? null;
        this.started_at = data.started_at ?? null;
        this.finished_at = data.finished_at ?? null;
        this.acknowledged = data.acknowledged ?? false;
        this.response = data.response ?? null;
        this.error = data.error ?? null;
        this.created_at = data.created_at ?? Date.now();
        this.updated_at = data.updated_at ?? Date.now();
        this.deleted_at = data.deleted_at ?? null;
        this.id = data.id ?? 0;
    }
}

export default ChatCommand;