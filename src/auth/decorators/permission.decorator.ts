// noinspection JSUnusedGlobalSymbols

import { CustomDecorator, SetMetadata } from "@nestjs/common";

export const PERMISSION_KEY = "permission";
export const Permission = (permission: string): CustomDecorator => SetMetadata(PERMISSION_KEY, permission);
