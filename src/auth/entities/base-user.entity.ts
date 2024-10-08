// noinspection JSUnusedGlobalSymbols

import { IUserEntity } from "hichchi-nestjs-common/interfaces";

export class BaseUserEntity implements IUserEntity {
    id: any;

    username?: string;

    email?: string;

    password: string;

    salt: string;

    role?: string;
}
