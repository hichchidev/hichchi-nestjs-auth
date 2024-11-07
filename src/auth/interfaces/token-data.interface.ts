export interface IJwtPayload {
    sub: string | number;
    username: string;
    email?: string;
}
