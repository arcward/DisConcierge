interface IDiscordMessage {
    created_at?: number;
    updated_at?: number;
    deleted_at?: Date | null;
    id: number;
    message_id: string;
    content: string;
    channel_id: string;
    guild_id: string;
    user_id: string;
    username: string;
    global_name: string;
    interaction_id: string;
    referenced_message_id: string;
    payload: string;
}


class DiscordMessage implements IDiscordMessage {
    created_at?: number;
    updated_at?: number;
    deleted_at?: Date | null;
    id: number;
    message_id: string;
    content: string;
    channel_id: string;
    guild_id: string;
    user_id: string;
    username: string;
    global_name: string;
    interaction_id: string;
    referenced_message_id: string;
    payload: string;

    constructor(data: Partial<IDiscordMessage> = {}) {
        this.created_at = data.created_at ?? Date.now();
        this.updated_at = data.updated_at ?? Date.now();
        this.deleted_at = data.deleted_at ?? null;
        this.id = data.id ?? 0;
        this.message_id = data.message_id ?? '';
        this.content = data.content ?? '';
        this.channel_id = data.channel_id ?? '';
        this.guild_id = data.guild_id ?? '';
        this.user_id = data.user_id ?? '';
        this.username = data.username ?? '';
        this.global_name = data.global_name ?? '';
        this.interaction_id = data.interaction_id ?? '';
        this.referenced_message_id = data.referenced_message_id ?? '';
        this.payload = data.payload ?? '';
    }
}

export default DiscordMessage;