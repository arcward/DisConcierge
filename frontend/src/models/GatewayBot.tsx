

export class SessionStartLimit {
    total: number;
    remaining: number;
    reset_after: number;
    max_concurrency: number;

    constructor(data: Partial<SessionStartLimit> = {}) {
        this.total = data.total || 0;
        this.remaining = data.remaining || 0;
        this.reset_after = data.reset_after || 0;
        this.max_concurrency = data.max_concurrency || 0;
    }
}

export class GatewayBot {
    url: string;
    shards: number;
    session_start_limit: SessionStartLimit;

    constructor(data: Partial<GatewayBot> = {}) {
        this.url = data.url || '';
        this.shards = data.shards || 0;
        this.session_start_limit = new SessionStartLimit(data.session_start_limit);
    }

}

export default GatewayBot;