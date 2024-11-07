// noinspection JSUnusedGlobalSymbols

import { DynamicModule, Global, Inject, Logger, Module } from "@nestjs/common";
import { AuthService, JwtTokenService, UserCacheService } from "./services";
import { UserServiceExistingProvider, UserServiceFactoryProvider } from "./providers";
import { JwtModule } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { IAuthOptions, IUserService } from "./interfaces";
import { AUTH_OPTIONS, USER_SERVICE } from "./tokens";
import { AuthController } from "./controllers";
import * as redisStore from "cache-manager-redis-store";
import { JwtStrategy, LocalStrategy } from "./strategies";
import { JwtAuthGuard } from "./guards";
import { RedisCacheModule } from "hichchi-nestjs-common/cache";
import { AuthField, AuthMethod } from "./enums";
import { RegisterDto, ViewDto } from "./dtos";
import { exit } from "process";
import { TokenVerifyService } from "./services/token-verify.service";

// noinspection SpellCheckingInspection
export const DEFAULT_SECRET = "3cGnEj4Kd1ENr8UcX8fBKugmv7lXmZyJtsa_fo-RcIk";

@Global()
@Module({})
export class HichchiAuthModule {
    constructor(@Inject(USER_SERVICE) userService: IUserService, @Inject(AUTH_OPTIONS) options: IAuthOptions) {
        HichchiAuthModule.validateUserServiceProvider(userService, options);
    }

    /**
     * Register the HichchiAuthModule asynchronously
     *
     * This method is used to register the `HichchiAuthModule` asynchronously.
     * It takes a user service provider and authentication options as arguments and returns a dynamic module.
     * The user service provider can be either `UserServiceFactoryProvider` or `UserServiceExistingProvider`.
     * The `UserService` used in the user service provider should implement the `IUserService` interface provided by the `hichchi-nestjs-auth` package.
     *
     * The authentication options include the redis, jwt, cookies, socket, authMethod, authField, disableRegistration, registerDto, and viewDto.
     *
     * @example
     * ```typescript
     * @Module({
     *     imports: [
     *         HichchiAuthModule.registerAsync(
     *             // Using UserServiceFactoryProvider
     *             {
     *                 imports: [UserModule],
     *                 useFactory: (userService: UserService) => userService,
     *                 inject: [UserService],
     *             },
     *             { ... },
     *         ),
     *     ],
     *     controllers: [...],
     *     providers: [...],
     * })
     * export class AppModule {}
     * ```
     *
     * @example
     * ```typescript
     * @Module({
     *     imports: [
     *         HichchiAuthModule.registerAsync(
     *             // Using UserServiceExistingProvider
     *             {
     *                 imports: [UserModule],
     *                 useExisting: UserService,
     *             },
     *             { ... },
     *         ),
     *     ],
     *     controllers: [...],
     *     providers: [...],
     * })
     * export class AppModule {}
     *
     * ```
     *
     * @param {UserServiceFactoryProvider | UserServiceExistingProvider} userServiceProvider The user service provider
     * @param {IAuthOptions} authOptions The authentication options
     * @returns {DynamicModule} The dynamic module
     */
    public static registerAsync(
        userServiceProvider: UserServiceFactoryProvider | UserServiceExistingProvider,
        authOptions: IAuthOptions,
    ): DynamicModule {
        this.validateAuthOptions(authOptions);

        const options: Required<IAuthOptions> = {
            redis: authOptions.redis?.url
                ? {
                      ttl: authOptions.redis?.ttl,
                      store: authOptions.redis?.store || redisStore,
                      url: authOptions.redis?.url,
                      prefix: authOptions.redis?.prefix,
                  }
                : {
                      ttl: authOptions.redis?.ttl,
                      store: authOptions.redis?.store || redisStore,
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
            passwordResetExp: authOptions.passwordResetExp || 60 * 15,
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
                TokenVerifyService,
                ...((userServiceProvider as UserServiceFactoryProvider).inject ?? []),
            ],
            controllers: [AuthController],
            exports: [
                AuthService,
                JwtStrategy,
                JwtAuthGuard,
                UserCacheService,
                TokenVerifyService,
                {
                    provide: AUTH_OPTIONS,
                    useValue: options,
                },
            ],
        };
    }

    private static validateAuthOptions(options: IAuthOptions): boolean {
        if (!options) {
            this.logOptionError();
        }
        return true;
    }

    private static validateUserServiceProvider(userService: IUserService, options: IAuthOptions): void {
        if (!userService.registerUser) {
            this.logProviderError("registerUser");
        } else if (!userService.getUserById) {
            this.logProviderError("getUserById");
        } else if (!userService.updateUserById) {
            this.logProviderError("registerUser");
        } else if (
            (options.authField === AuthField.EMAIL || options.authField === AuthField.BOTH) &&
            !userService.getUserByEmail
        ) {
            this.logProviderError("getUserByEmail", "EMAIL");
        } else if (
            (options.authField === AuthField.USERNAME || options.authField === AuthField.BOTH) &&
            !userService.getUserByUsername
        ) {
            this.logProviderError("getUserByUsername", "USERNAME");
        } else if (options.authField === AuthField.BOTH && !userService.getUserByUsernameOrEmail) {
            this.logProviderError("getUserByUsernameOrEmail", "BOTH");
        }
    }

    private static logOptionError(): void {
        const error = "";
        this.logAndExit(error);
    }

    private static logProviderError(method: string, authField?: string): void {
        const error =
            `UserService does not implements the IUserService interface properly\n\n` +
            `    UserService provided to HichchiAuthModule.registerAsync() does not implements the ${method} method in IUserService interface provided by hichchi-nestjs-auth\n\n` +
            `${authField ? `    ${method} method should be implemented when authField is set to ${authField}${authField === "BOTH" ? "" : " or BOTH\n"}` : ""}`;
        this.logAndExit(error);
    }

    static logAndExit(error: string): void {
        Logger.error(error);
        exit(1);
    }
}
