// noinspection JSUnusedGlobalSymbols

import { IUserEntity } from "hichchi-nestjs-common/interfaces";

export class BaseUserEntity implements IUserEntity {
    id: any;

    firstName: string;

    lastName: string;

    fullName: string;

    username?: string;

    email?: string;

    password: string;

    salt: string;

    role?: string;

    emailVerified?: boolean;

    avatar?: string;

    profileData?: object;
}
