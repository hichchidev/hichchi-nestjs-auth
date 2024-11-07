import { Injectable } from "@nestjs/common";
import { RedisCacheService } from "hichchi-nestjs-common/cache";

const PASSWORD_RESET_USER_KEY = (userId: string | number): string => `password-reset:userId:${userId}`;
const PASSWORD_RESET_TOKEN_KEY = (token: string | number): string => `password-reset:token:${token}`;

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
}
