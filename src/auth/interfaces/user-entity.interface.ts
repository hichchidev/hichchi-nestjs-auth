export interface IUserEntity {
    id: any;
    username: string;
    password: string;
    salt: string;
    email?: string;
    role?: string;
}
