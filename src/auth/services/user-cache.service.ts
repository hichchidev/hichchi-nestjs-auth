import { Injectable } from "@nestjs/common";
import { ICacheUser } from "../interfaces";
import { RedisCacheService } from "hichchi-nestjs-common/cache";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

const USER_PREFIX = (userId: number): string => `user-${userId}`;

@Injectable()
export class UserCacheService {
    constructor(private readonly cacheService: RedisCacheService) {}

    async setUser(user: ICacheUser): Promise<boolean> {
        return await this.cacheService.set<Omit<IUserEntity, "password" | "salt">>(USER_PREFIX(user.id), user);
    }

    async getUser(id: number): Promise<ICacheUser> {
        return await this.cacheService.get<ICacheUser>(USER_PREFIX(id));
    }

    async clearUser(id: number): Promise<boolean> {
        return await this.cacheService.delete(USER_PREFIX(id));
    }
}
