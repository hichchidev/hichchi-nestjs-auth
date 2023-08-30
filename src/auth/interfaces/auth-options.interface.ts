import { CacheStore, CacheStoreFactory } from "@nestjs/cache-manager/dist/interfaces/cache-manager.interface";
import { RegisterDto } from "../dtos";

export interface RedisCacheOptions {
    store: string | CacheStoreFactory | CacheStore;
    ttl: number;
    host: string;
    port: number;
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
    registerDto?: typeof RegisterDto;
}
