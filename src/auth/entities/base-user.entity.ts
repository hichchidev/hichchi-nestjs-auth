// noinspection JSUnusedGlobalSymbols

import { IUserEntity } from "../interfaces";

export class BaseUserEntity implements IUserEntity {
    id: any;

    username: string;

    password: string;

    salt: string;

    role?: string;
}
