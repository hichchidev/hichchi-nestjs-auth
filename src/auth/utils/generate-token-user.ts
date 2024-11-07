import { TokenUser } from "../types";
import { ICacheUser } from "../interfaces";

/**
 * Generate token user
 * @param {ICacheUser} cacheUser Cache user
 * @param {string} accessToken Access token
 * @param {string} socketId Socket id
 * @returns {TokenUser} Token user
 */
export function generateTokenUser(cacheUser: ICacheUser, accessToken?: string, socketId?: string): TokenUser {
    const { sessions, ...user } = cacheUser;
    const session = sessions.find((session) => session.accessToken === accessToken);
    return {
        ...user,
        accessToken,
        refreshToken: session?.refreshToken,
        sessionId: session?.sessionId,
        socketId: socketId,
    };
}
