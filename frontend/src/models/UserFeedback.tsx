export class UserFeedback {
    id: number;
    created_at: number;
    updated_at: number;
    deleted_at: number | null;
    chat_command_id: number;
    user_id: string;
    custom_id: string;
    type: string;
    description: string;
    detail: string;

    constructor(data: Partial<UserFeedback> = {}) {
        this.id = data.id || 0;
        this.created_at = data.created_at || 0;
        this.updated_at = data.updated_at || 0;
        this.deleted_at = data.deleted_at || null;
        this.chat_command_id = data.chat_command_id || 0;
        this.user_id = data.user_id || '';
        this.custom_id = data.custom_id || '';
        this.type = data.type || '';
        this.description = data.description || '';
        this.detail = data.detail || '';
    }

    getCreatedAtDate(): Date {
        return new Date(this.created_at);
    }

    getUpdatedAtDate(): Date {
        return new Date(this.updated_at);
    }

    getDeletedAtDate(): Date | null {
        return this.deleted_at ? new Date(this.deleted_at) : null;
    }
}

export class UserFeedbackResponse {
    total: number;
    offset: number;
    limit: number;
    feedback: UserFeedback[];

    constructor(data: Partial<UserFeedbackResponse> = {}) {
        this.total = data.total || 0;
        this.offset = data.offset || 0;
        this.limit = data.limit || 0;
        this.feedback = (data.feedback || []).map(item => new UserFeedback(item));
    }

    getTotalPages(): number {
        return Math.ceil(this.total / this.limit);
    }

    getCurrentPage(): number {
        return Math.floor(this.offset / this.limit) + 1;
    }

    hasNextPage(): boolean {
        return this.getCurrentPage() < this.getTotalPages();
    }

    hasPreviousPage(): boolean {
        return this.getCurrentPage() > 1;
    }
}