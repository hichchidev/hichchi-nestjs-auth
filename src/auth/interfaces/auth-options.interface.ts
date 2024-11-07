import { CacheStore, CacheStoreFactory } from "@nestjs/cache-manager/dist/interfaces/cache-manager.interface";
import { RegisterDto } from "../dtos";
import { AuthMethod } from "../enums";
import { AuthField } from "../enums";
import { ViewDto } from "../dtos";

export interface IRedisCacheOptions {
    store?: string | CacheStoreFactory | CacheStore;
    ttl: number;
    host?: string;
    port?: number;
    auth_pass?: string;
    url?: string;
    prefix?: string;
}

export interface IAuthOptions {
    redis?: IRedisCacheOptions;
    jwt?: {
        secret?: string;
        expiresIn?: number;
        refreshSecret?: string;
        refreshExpiresIn?: number;
    };
    cookies?: {
        secret?: string;
        sameSite?: boolean | "lax" | "strict" | "none";
        secure?: boolean;
    };
    socket?: {
        idKey: string;
    };
    checkEmailVerified?: boolean;
    emailVerifyRedirect?: string;
    passwordResetExp?: number;
    authMethod?: AuthMethod;
    authField?: AuthField;
    registerDto?: typeof RegisterDto;
    viewDto?: typeof ViewDto;
    disableRegistration?: boolean;
}
