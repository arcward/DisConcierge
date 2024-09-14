interface ILoggedIn {
    username: string;
}

export class LoggedInModel implements ILoggedIn {
    username: string;

    constructor(data: ILoggedIn) {
        this.username = data.username;
    }
}

export default LoggedInModel;
