import { CacheStore, CacheStoreFactory } from "@nestjs/cache-manager/dist/interfaces/cache-manager.interface";
import { RegisterDto } from "../dtos";
import { AuthType } from "../enums/auth-type.enum";
import { AuthBy } from "../enums/auth-by.enum";

export interface RedisCacheOptions {
    store?: string | CacheStoreFactory | CacheStore;
    ttl: number;
    host?: string;
    port?: number;
    auth_pass?: string;
    url?: string;
    prefix?: string;
}

export interface IAuthOptions {
    redis?: RedisCacheOptions;
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
    authType?: AuthType;
    authBy?: AuthBy;
    registerDto?: typeof RegisterDto;
}
