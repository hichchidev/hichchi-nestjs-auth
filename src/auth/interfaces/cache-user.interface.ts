import { IUserEntity } from "hichchi-nestjs-common/interfaces";

export interface IUserSession {
    accessToken: string;
    refreshToken: string;
}

export interface ICacheUser extends Omit<IUserEntity, "password" | "salt"> {
    sessions: IUserSession[];
}
