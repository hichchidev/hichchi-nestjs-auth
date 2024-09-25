// noinspection JSUnusedGlobalSymbols

import { Module, DynamicModule, Global } from "@nestjs/common";
import { AuthService } from "./services";
import { UserServiceFactoryProvider, UserServiceExistingProvider } from "./providers";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { IAuthOptions } from "./interfaces";
import { AUTH_OPTIONS, USER_SERVICE } from "./tokens";
import { AuthController } from "./controllers";
import * as redisStore from "cache-manager-redis-store";
import { LocalStrategy } from "./strategies";
import { JwtStrategy } from "./strategies";
import { JwtAuthGuard } from "./guards";
import { RedisCacheModule } from "hichchi-nestjs-common/cache";
import { AuthMethod } from "./enums";
import { AuthField } from "./enums";
import { UserCacheService } from "./services";
import { JwtTokenService } from "./services";
import { RegisterDto, ViewDto } from "./dtos";

// noinspection SpellCheckingInspection
export const DEFAULT_SECRET = "3cGnEj4Kd1ENr8UcX8fBKugmv7lXmZyJtsa_fo-RcIk";

@Global()
@Module({})
export class HichchiAuthModule {
    static registerAsync(
        userServiceProvider: UserServiceFactoryProvider | UserServiceExistingProvider,
        authOptions: IAuthOptions,
    ): DynamicModule {
        // noinspection SpellCheckingInspection
        const options: Required<IAuthOptions> = {
            redis: authOptions.redis?.url
                ? {
                      ttl: authOptions.redis?.ttl || 10,
                      store: authOptions.redis?.store || redisStore,
                      url: authOptions.redis?.url,
                      prefix: authOptions.redis?.prefix,
                  }
                : {
                      store: authOptions.redis?.store || redisStore,
                      ttl: authOptions.redis?.ttl || 10,
                      host: authOptions.redis?.host || "localhost",
                      port: authOptions.redis?.port || 6379,
                      auth_pass: authOptions.redis?.auth_pass,
                      prefix: authOptions.redis?.prefix,
                  },
            jwt: {
                secret: authOptions.jwt?.secret || DEFAULT_SECRET,
                expiresIn: authOptions.jwt?.expiresIn || 60 * 60 * 24 * 30,
                refreshSecret: authOptions.jwt?.refreshSecret || DEFAULT_SECRET,
                refreshExpiresIn: authOptions.jwt?.refreshExpiresIn || 60 * 60 * 24 * 60,
            },
            cookies: {
                secret: authOptions.cookies?.secret || authOptions.cookies?.secure ? DEFAULT_SECRET : undefined,
                sameSite: authOptions.cookies?.sameSite || "none",
                secure: Boolean(authOptions.cookies?.secure),
            },
            socket: {
                idKey: authOptions.socket?.idKey || "Socket-Id",
            },
            authMethod: authOptions.authMethod ?? AuthMethod.JWT,
            authField: authOptions.authField ?? AuthField.BOTH,
            disableRegistration: authOptions.disableRegistration ?? false,
            registerDto: authOptions.registerDto ?? RegisterDto,
            viewDto: authOptions.viewDto ?? ViewDto,
        };

        return {
            module: HichchiAuthModule,
            imports: [
                RedisCacheModule.registerAsync(options.redis),
                JwtModule.register(options.jwt),
                PassportModule,
                ...(userServiceProvider.imports ?? []),
            ],
            providers: [
                {
                    provide: USER_SERVICE,
                    useFactory: (userServiceProvider as UserServiceFactoryProvider).useFactory,
                    useExisting: (userServiceProvider as UserServiceExistingProvider).useExisting,
                    inject: (userServiceProvider as UserServiceFactoryProvider).inject,
                },
                {
                    provide: AUTH_OPTIONS,
                    useValue: options,
                },
                AuthService,
                UserCacheService,
                JwtTokenService,
                LocalStrategy,
                JwtStrategy,
                JwtAuthGuard,
                ...((userServiceProvider as UserServiceFactoryProvider).inject ?? []),
            ],
            controllers: [AuthController],
            exports: [
                AuthService,
                JwtStrategy,
                JwtAuthGuard,
                UserCacheService,
                {
                    provide: AUTH_OPTIONS,
                    useValue: options,
                },
            ],
        };
    }
}
