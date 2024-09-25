// noinspection JSUnusedGlobalSymbols

import { CustomDecorator, SetMetadata } from "@nestjs/common";

export const ROLES_KEY = "roles";
export const Roles = (...roles: any[]): CustomDecorator => SetMetadata(ROLES_KEY, roles);
