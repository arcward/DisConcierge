interface OpenAIAPILog {
    chat_command_id: number | null;
    request_started: number;
    request_ended: number;
    request_payload: string;
    response_payload: string;
    headers: string;
    error: string;
    id: number;
    created_at?: number;
    updated_at?: number;
    deleted_at?: Date | null;
}


class OpenAIAPILogClass implements OpenAIAPILog {
    chat_command_id: number | null;
    request_started: number;
    request_ended: number;
    request_payload: string;
    response_payload: string;
    headers: string;
    error: string;
    id: number;
    created_at?: number;
    updated_at?: number;
    deleted_at?: Date | null;

    constructor(data: Partial<OpenAIAPILog> = {}) {
        this.chat_command_id = data.chat_command_id ?? null;
        this.request_started = data.request_started ?? 0;
        this.request_ended = data.request_ended ?? 0;
        this.request_payload = data.request_payload ?? '';
        this.response_payload = data.response_payload ?? '';
        this.headers = data.headers ?? '';
        this.error = data.error ?? '';
        this.id = data.id ?? 0;
        this.created_at = data.created_at ?? Date.now();
        this.updated_at = data.updated_at ?? Date.now();
        this.deleted_at = data.deleted_at ?? null;
    }
}

export default OpenAIAPILogClass;



