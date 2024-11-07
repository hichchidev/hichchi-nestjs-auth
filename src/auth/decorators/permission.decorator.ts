// noinspection JSUnusedGlobalSymbols

import { CustomDecorator, SetMetadata } from "@nestjs/common";

export const PERMISSION_KEY = "permission";

/**
 * Permission decorator
 *
 * This decorator is used to set the permission for a route.
 *
 * @example
 * ```typescript
 * @Controller("user")
 * export class UserController {
 *     @Get()
 *     @Permission(Permission.GET_USER)
 *     async getUsers(): Promise<User[]> {
 *         // Implementation
 *     }
 * }
 *
 * ```
 *
 * @param {string} permission permission
 * @returns {CustomDecorator} CustomDecorator
 */
export function Permission(permission: string): CustomDecorator {
    return SetMetadata(PERMISSION_KEY, permission);
}
