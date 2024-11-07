import { Injectable } from "@nestjs/common";
import { RedisCacheService } from "hichchi-nestjs-common/cache";

const PASSWORD_RESET_USER_KEY = (userId: string | number): string => `password-reset:userId:${userId}`;
const PASSWORD_RESET_TOKEN_KEY = (token: string | number): string => `password-reset:token:${token}`;

const EMAIL_VERIFY_USER_KEY = (userId: string | number): string => `email-verify:userId:${userId}`;
const EMAIL_VERIFY_TOKEN_KEY = (token: string | number): string => `email-verify:token:${token}`;

@Injectable()
export class TokenVerifyService {
    constructor(private readonly cacheService: RedisCacheService) {}

    async savePasswordResetToken(userId: string | number, token: string | number, ttl?: number): Promise<boolean> {
        const clear = await this.clearPasswordResetTokenByUserId(userId);
        const byId = await this.cacheService.set<string | number>(PASSWORD_RESET_USER_KEY(userId), token, ttl);
        const byToken = await this.cacheService.set<string | number>(PASSWORD_RESET_TOKEN_KEY(token), userId, ttl);
        return clear && byId && byToken;
    }

    async getPasswordResetTokenByUserId(userId: string | number): Promise<string | number> {
        return await this.cacheService.get<string | number>(PASSWORD_RESET_USER_KEY(userId));
    }

    async getUserIdByPasswordResetToken(token: string | number): Promise<string | number> {
        return await this.cacheService.get<string | number>(PASSWORD_RESET_TOKEN_KEY(token));
    }

    async clearPasswordResetTokenByUserId(userId: string | number): Promise<boolean> {
        const token = await this.getPasswordResetTokenByUserId(userId);
        const byId = await this.cacheService.delete(PASSWORD_RESET_USER_KEY(userId));
        const byToken = await this.cacheService.delete(PASSWORD_RESET_TOKEN_KEY(token));
        return byId && byToken;
    }

    async saveEmailVerifyToken(userId: string | number, token: string | number, ttl?: number): Promise<boolean> {
        const clear = await this.clearEmailVerifyTokenByUserId(userId);
        const byId = await this.cacheService.set<string | number>(EMAIL_VERIFY_USER_KEY(userId), token, ttl);
        const byToken = await this.cacheService.set<string | number>(EMAIL_VERIFY_TOKEN_KEY(token), userId, ttl);
        return clear && byId && byToken;
    }

    async getEmailVerifyTokenByUserId(userId: string | number): Promise<string | number> {
        return await this.cacheService.get<string | number>(EMAIL_VERIFY_USER_KEY(userId));
    }

    async getUserIdByEmailVerifyToken(token: string | number): Promise<string | number> {
        return await this.cacheService.get<string | number>(EMAIL_VERIFY_TOKEN_KEY(token));
    }

    async clearEmailVerifyTokenByUserId(userId: string | number): Promise<boolean> {
        const token = await this.getEmailVerifyTokenByUserId(userId);
        const byId = await this.cacheService.delete(EMAIL_VERIFY_USER_KEY(userId));
        const byToken = await this.cacheService.delete(EMAIL_VERIFY_TOKEN_KEY(token));
        return byId && byToken;
    }
}
