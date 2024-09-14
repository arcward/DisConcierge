import {TruncationStrategy} from './RuntimeConfigModel';


interface IChatCommandUsage {
    limit_6h: number;
    attempted_6h: number;
    billable_6h: number;
    remaining_6h: number;
    prompt_tokens_6h: number;
    completion_tokens_6h: number;
    total_tokens_6h: number;
    state_6h: { [key: string]: number };  // Assuming ChatCommandState is a string in TypeScript
    private_6h: number;
    threads_6h: number;

    commands_available: boolean;
    commands_available_at: string;  // Assuming time.Time is serialized as a string
}

class ChatCommandUsage implements IChatCommandUsage {
    limit_6h: number = 0;
    attempted_6h: number = 0;
    billable_6h: number = 0;
    remaining_6h: number = 0;
    prompt_tokens_6h: number = 0;
    completion_tokens_6h: number = 0;
    total_tokens_6h: number = 0;
    state_6h: { [key: string]: number } = {};
    private_6h: number = 0;
    threads_6h: number = 0;

    commands_available: boolean = false;
    commands_available_at: string = '';


    constructor(data: Partial<ChatCommandUsage> = {}) {
        Object.assign(this, data);
    }
}

interface IUserStatsModel {
    chat_command_usage: IChatCommandUsage | null;
    clear_commands: number;
    reports: Record<string, number>;
}

interface IUserModel {
    id: string;
    username: string;
    global_name: string;
    bot: boolean;
    content: string;

    thread_id: string | null;
    priority: boolean;
    ignored: boolean;

    last_seen: number | null;

    user_chat_command_limit_6h: number | null;
    openai_max_completion_tokens: number | null;
    openai_max_prompt_tokens: number | null;
    openai_truncation_strategy_type: TruncationStrategy | "";
    openai_truncation_strategy_last_messages: number | null;
    assistant_instructions: string;
    assistant_additional_instructions: string;
    assistant_temperature: number | null;
    assistant_poll_interval: string | null;
    assistant_max_poll_interval: string | null;

    created_at: number;
    updated_at: number;
    deleted_at: string | null;
    stats: IUserStatsModel | null;
}

export class UserStatsModel implements IUserStatsModel {
    chat_command_usage: ChatCommandUsage | null;
    clear_commands: number;
    reports: Record<string, number>;

    constructor(data: Partial<IUserStatsModel>) {
        this.chat_command_usage = data.chat_command_usage ? new ChatCommandUsage(data.chat_command_usage) : null;
        this.clear_commands = data.clear_commands || 0;
        this.reports = data.reports || {};
    }
}


export class UserModel implements IUserModel {
    id: string;
    username: string;
    global_name: string;
    bot: boolean;
    content: string;

    thread_id: string | null;
    priority: boolean;
    ignored: boolean;

    last_seen: number | null;

    user_chat_command_limit_6h: number | null;

    openai_truncation_strategy_type: TruncationStrategy | "";

    openai_max_completion_tokens: number | null;
    openai_max_prompt_tokens: number | null;
    openai_truncation_strategy_last_messages: number | null;
    assistant_instructions: string;
    assistant_additional_instructions: string;
    assistant_temperature: number | null;
    assistant_poll_interval: string | null;
    assistant_max_poll_interval: string | null;

    created_at: number;
    updated_at: number;
    deleted_at: string | null;
    stats: UserStatsModel | null;

    constructor(data: Partial<IUserModel>) {
        this.id = data.id || '';
        this.username = data.username || '';

        this.priority = data.priority || false;
        this.thread_id = data.thread_id || null;
        this.ignored = data.ignored || false;
        this.content = data.content || '';
        this.last_seen = data.last_seen || null;

        this.global_name = data.global_name || '';

        this.bot = data.bot || false;
        this.user_chat_command_limit_6h = data.user_chat_command_limit_6h || null;
        this.created_at = data.created_at || 0;
        this.updated_at = data.updated_at || 0;
        this.deleted_at = data.deleted_at || null;
        this.stats = data.stats ? new UserStatsModel(data.stats) : null;

        this.openai_max_completion_tokens = data.openai_max_completion_tokens || null;
        this.openai_max_prompt_tokens = data.openai_max_prompt_tokens || null;
        this.openai_truncation_strategy_type = data.openai_truncation_strategy_type || '';
        this.openai_truncation_strategy_last_messages = data.openai_truncation_strategy_last_messages || null;
        this.assistant_instructions = data.assistant_instructions || '';
        this.assistant_additional_instructions = data.assistant_additional_instructions || '';
        this.assistant_temperature = data.assistant_temperature || null;
        this.assistant_poll_interval = data.assistant_poll_interval || null;
        this.assistant_max_poll_interval = data.assistant_max_poll_interval || null;
    }
}


export default UserModel;
