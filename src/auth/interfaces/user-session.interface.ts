export interface IUserSession {
    sessionId: string;
    accessToken: string;
    refreshToken: string;
    frontendUrl?: string;
}
