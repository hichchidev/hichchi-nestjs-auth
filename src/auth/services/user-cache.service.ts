import { Injectable } from "@nestjs/common";
import { ICacheUser } from "../interfaces";
import { RedisCacheService } from "hichchi-nestjs-common/cache";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

const USER_PREFIX = (userId: string | number): string => `user-${userId}`;

@Injectable()
export class UserCacheService {
    constructor(private readonly cacheService: RedisCacheService) {}

    /**
     * Set user in cache
     * @param {ICacheUser} user User to set in cache
     * @returns {Promise<boolean>} `true` if user is set in cache, otherwise `false`
     */
    async setUser(user: ICacheUser): Promise<boolean> {
        return await this.cacheService.set<Omit<IUserEntity, "password" | "salt">>(USER_PREFIX(user.id), user);
    }

    /**
     * Get a user from cache
     * @param {number} id User id
     * @returns {Promise<ICacheUser|undefined>} User from cache
     */
    async getUser(id: string | number): Promise<ICacheUser | undefined> {
        return await this.cacheService.get<ICacheUser>(USER_PREFIX(id));
    }

    /**
     * Clear user from cache
     * @param {number} id User id
     * @returns {Promise<boolean>} `true` if user is cleared from cache, otherwise `false`
     */
    async clearUser(id: string | number): Promise<boolean> {
        return await this.cacheService.delete(USER_PREFIX(id));
    }
}
