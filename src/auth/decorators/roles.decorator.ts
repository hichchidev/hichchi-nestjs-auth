// noinspection JSUnusedGlobalSymbols

import { CustomDecorator, SetMetadata } from "@nestjs/common";

export const ROLES_KEY = "roles";

/**
 * Roles decorator
 *
 * This decorator is used to set the roles for a route.
 *
 * @example
 * ```typescript
 * @Controller("user")
 * export class UserController {
 *     @Get()
 *     @Roles(Role.ADMIN, Role.USER)
 *     async getUsers(): Promise<User[]> {
 *         // Implementation
 *     }
 * }
 *
 * ```
 *
 * @param roles Comma separated roles
 * @returns {CustomDecorator} CustomDecorator
 */
export function Roles(...roles: string[]): CustomDecorator {
    return SetMetadata(ROLES_KEY, roles);
}
