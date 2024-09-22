import UserModel                                 from '../models/User';
import UserHistoryModel                          from '../models/UserHistoryModel';
import LoggedInModel                             from '../models/LoggedInModel';
import HealthCheck                               from '../models/HealthCheck';
import RuntimeConfigModel, {RuntimeConfigUpdate} from '../models/RuntimeConfigModel';
import axios, {AxiosError}                       from 'axios';
import ChatCommand                               from '../models/ChatCommand';
import DiscordMessage                            from '../models/DiscordMessage';
import {UserFeedback, UserFeedbackResponse}      from '../models/UserFeedback';
import ChatCommandDetail                         from '../models/ChatCommandDetail';
import GatewayBot                                from '../models/GatewayBot';

const DEFAULT_API_HOST = 'https://localhost';
const DEFAULT_API_PORT = '5000';


const apiClient = axios.create({

    headers: {
        'Content-Type': 'application/json',
    }, withCredentials: true,
});


apiClient.interceptors.request.use(config => {
    const host = process.env.REACT_APP_API_HOST || DEFAULT_API_HOST;
    const port = process.env.REACT_APP_API_PORT || DEFAULT_API_PORT;
    config.baseURL = `${host}:${port}`;
    return config;

}, error => {
    return Promise.reject(error);
});

// Add a response interceptor to handle errors globally
apiClient.interceptors.response.use(response => response, error => {
    if (error instanceof AxiosError) {
        if (error.response?.status === 401) {
            console.error('Unauthorized request', window.location.href);
        } else {
            console.error('Error:', error.message);
        }
    }
    return Promise.reject(error);
});

const api = {
    getGatewayBot: async (): Promise<GatewayBot> => {
        const response = await apiClient.get('/api/discord/gateway/bot');
        return new GatewayBot(response.data);
    },
    healthcheck: async (): Promise<HealthCheck> => {
        const response = await apiClient.get('/healthz');
        const t = new HealthCheck(response.data);
        return t
    },
    getConfig: async () => {
        const response = await apiClient.get('/api/config');
        const t = new RuntimeConfigModel(response.data);
        return t
    },
    login: async (username: string, password: string): Promise<LoggedInModel> => {
        const response = await apiClient.post(
            '/login',
            {username, password},
            {withCredentials: true}
        );
        return new LoggedInModel(response.data);
    },
    logout: () => {
        return apiClient.post('/logout');
    },
    loggedIn: async (): Promise<LoggedInModel> => {
        const response = await apiClient.get('/api/logged_in');
        return new LoggedInModel(response.data);
    },
    registerCommands: () => {
        return apiClient.post('/api/discord/register_commands');
    },
    clearThreads: () => {
        return apiClient.post('/api/clear_threads');
    },
    quit: () => {
        return apiClient.post('/api/quit');
    },
    getUsers: async (
        include_stats: boolean = true,
        order: string = "asc",
        limit: number = 25,
        offset: number = 0
    ): Promise<UserModel[]> => {
        const response = await apiClient.get(
            '/api/users',
            {
                params: {
                    include_stats: include_stats,
                    limit: limit,
                    offset: offset,
                    order: order,
                }
            }
        );
        const usersList = response.data.map((userData: Partial<UserModel>) => new UserModel(userData));
        return usersList;
    },
    getChatCommands: async (
        order: string = "desc",
        limit: number = 25,
        offset: number = 0
    ): Promise<ChatCommand[]> => {
        const response = await apiClient.get(
            '/api/chat_commands',
            {
                params: {
                    limit: limit,
                    offset: offset,
                    order: order,
                }
            }
        );
        const chatCommandList = response.data.map((commandData: Partial<ChatCommand>) => new ChatCommand(
            commandData));
        return chatCommandList;
    },
    getChatCommand: async (id: string): Promise<ChatCommandDetail> => {
        const response = await apiClient.get(`/api/chat_command/${id}`);
        const chatCommand = new ChatCommandDetail(response.data);
        return chatCommand;
    },
    getDiscordMessages: async (
        order: string = "desc",
        limit: number = 25,
        offset: number = 0
    ): Promise<DiscordMessage[]> => {
        const response = await apiClient.get(
            '/api/discord_messages',
            {
                params: {
                    limit: limit,
                    offset: offset,
                    order: order,
                }
            }
        );
        const msgList = response.data.map((msgData: Partial<ChatCommand>) => new DiscordMessage(
            msgData));
        return msgList;
    },
    reloadUsers: async (): Promise<any> => {
        const response = await apiClient.post('/api/users/reload');

        return response.data;
    },
    getUserHistory: async (userId: string, sort = 'desc', limit = 20, includeReports = false): Promise<UserHistoryModel[]> => {
        const response = await apiClient.get(`/api/user/${userId}/history?sort=${sort}&limit=${limit}&include_reports=${includeReports}`);
        const userHistory = response.data.map((uh: Partial<UserHistoryModel>) => new UserHistoryModel(
            uh));
        return userHistory;
    },
    getUser: async (userId: string): Promise<UserModel[]> => {
        const response = await apiClient.get(`/api/user/${userId}`);
        const user = response.data.map((uh: Partial<UserModel>) => new UserModel(uh));
        return user;
    },
    updateUser: async (userId: string, updatedData: Partial<UserModel>): Promise<UserModel> => {
        const response = await apiClient.patch(`/api/user/${userId}`, updatedData);
        return new UserModel(response.data);
    },
    updateBotState: async (updateData: RuntimeConfigUpdate): Promise<RuntimeConfigModel> => {
        const response = await apiClient.patch('/api/config', updateData);
        return new RuntimeConfigModel(response.data);
    },
    getUserFeedbackByID: async (userFeedbackID: number): Promise<UserFeedback> => {
        const response = await apiClient.get(`/api/user_feedback/${userFeedbackID}`);
        return new UserFeedback(response.data);
    },
    getUserFeedback: async (
        order: string = "desc",
        limit: number = 25,
        offset: number = 0,
        chatCommandId?: number,
        userId?: string
    ): Promise<UserFeedbackResponse> => {
        const params = new URLSearchParams({
            order,
            limit: limit.toString(),
            offset: offset.toString(),
        });

        if (chatCommandId) {
            params.append('chat_command_id', chatCommandId.toString());
        }

        if (userId) {
            params.append('user_id', userId);
        }

        const response = await apiClient.get(`/api/user_feedback?${params.toString()}`);
        const feedbackData = response.data;

        // Create UserFeedback instances
        const feedbackInstances = feedbackData.feedback.map((item: any) => new UserFeedback(item));

        return new UserFeedbackResponse({
            ...feedbackData,
            feedback: feedbackInstances
        });
    },
}

export default api;
