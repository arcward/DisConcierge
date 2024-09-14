interface IHealthCheck {
    paused: boolean;
    queue_size: number;
    discord_gateway_connected: boolean;
}


export class HealthCheck implements IHealthCheck {
    paused: boolean;
    queue_size: number;
    discord_gateway_connected: boolean;

    constructor(data: Partial<IHealthCheck>) {
        this.paused = data.paused || false;
        this.queue_size = data.queue_size || 0;
        this.discord_gateway_connected = data.discord_gateway_connected || false;
    }
}

export default HealthCheck;