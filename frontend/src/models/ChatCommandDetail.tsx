import ChatCommand from './ChatCommand';
import  OpenAIAPILog from './OpenAILogModel';

export class OpenAICreateThread extends OpenAIAPILog {}

export class OpenAICreateMessage extends OpenAIAPILog {}

export class OpenAIListMessages extends OpenAIAPILog {}

export class OpenAICreateRun extends OpenAIAPILog {}

export class OpenAIRetrieveRun extends OpenAIAPILog {}

export class OpenAIListRunSteps extends OpenAIAPILog {}

export class ChatCommandDetail {
    chat_command: ChatCommand;
    create_thread?: OpenAICreateThread;
    create_message?: OpenAICreateMessage;
    list_messages?: OpenAIListMessages[];
    create_run?: OpenAICreateRun;
    retrieve_runs?: OpenAIRetrieveRun[];
    list_run_steps?: OpenAIListRunSteps[];

    constructor(data: Partial<ChatCommandDetail> = {}) {
        this.chat_command = new ChatCommand(data.chat_command);
        this.create_thread = data.create_thread ? new OpenAICreateThread(data.create_thread) : undefined;
        this.create_message = data.create_message ? new OpenAICreateMessage(data.create_message) : undefined;
        this.list_messages = data.list_messages ? data.list_messages.map(msg => new OpenAIListMessages(msg)) : undefined;
        this.create_run = data.create_run ? new OpenAICreateRun(data.create_run) : undefined;
        this.retrieve_runs = data.retrieve_runs ? data.retrieve_runs.map(run => new OpenAIRetrieveRun(run)) : undefined;
        this.list_run_steps = data.list_run_steps ? data.list_run_steps.map(step => new OpenAIListRunSteps(step)) : undefined;
    }
}

export default ChatCommandDetail;