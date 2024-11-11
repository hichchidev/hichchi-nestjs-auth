/* eslint-disable @typescript-eslint/ban-types,@typescript-eslint/ban-ts-comment */
// noinspection JSUnusedGlobalSymbols

import { Strategy } from "passport-google-oauth2";
import { PassportStrategy } from "@nestjs/passport";
import { Inject, Injectable } from "@nestjs/common";
import { IAuthOptions } from "../interfaces";
import { AUTH_OPTIONS } from "../tokens";
import { AuthService } from "../services";
import { IGoogleProfile } from "../interfaces/google-profile.interface";
import { AuthStrategy } from "../enums/auth-strategies.enum";

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, AuthStrategy.GOOGLE) {
    constructor(
        @Inject(AUTH_OPTIONS) readonly authOptions: IAuthOptions,
        private readonly authService: AuthService,
    ) {
        super({
            authorizationURL: `https://accounts.google.com/o/oauth2/v2/auth`,
            clientID: authOptions.googleAuth.clientId || "no-id",
            clientSecret: authOptions.googleAuth.clientSecret || "no-secret",
            callbackURL: `${authOptions.googleAuth.callbackUrl}`,
            scope: "profile email",
            state: null,
        });
    }

    async validate(
        _accessToken: string,
        _refreshToken: string,
        profile: IGoogleProfile,
        done: Function,
    ): Promise<void> {
        const tokenUser = await this.authService.authenticateGoogle(profile);
        if (!tokenUser) {
            done(null, false);
        }
        done(null, tokenUser);
    }
}
