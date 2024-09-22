export interface IUserHistory {
    username: string;
    global_name: string;
    user_id: string;
    prompt: string;
    response?: string;
    error?: string;
    state: string;
    step: string;
    created_at: string;
    run_id: string;
    thread_id: string;
    run_status: string;
    chat_command_id: number;
    interaction_id: string;
    context: string;
    private: boolean;
    feedback: string;
}

export class UserHistoryModel implements IUserHistory {
    chat_command_id: number;
    username: string;
    global_name: string;
    user_id: string;
    prompt: string;
    response?: string;
    error?: string;
    created_at: string;
    run_id: string;
    state: string;
    step: string;
    thread_id: string;
    run_status: string;

    interaction_id: string;
    context: string;
    private: boolean;
    feedback: string;

    constructor(data: Partial<IUserHistory>) {
        this.user_id = data.user_id || '';
        this.global_name = data.global_name || '';
        this.username = data.username || '';
        this.prompt = data.prompt || '';
        this.response = data.response || '';
        this.error = data.error || '';
        this.created_at = data.created_at || '';
        this.run_id = data.run_id || '';
        this.thread_id = data.thread_id || '';
        this.run_status = data.run_status || '';
        this.state = data.state || '';
        this.step = data.step || '';
        this.chat_command_id = data.chat_command_id || 0;
        this.interaction_id = data.interaction_id || '';
        this.context = data.context || '';
        this.private = data.private || false;
        this.feedback = data.feedback || '';
    }

}


export default UserHistoryModel;