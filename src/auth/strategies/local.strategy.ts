import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { Inject, Injectable } from "@nestjs/common";
import { AuthService } from "../services";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { AUTH_OPTIONS } from "../tokens";
import { AuthField } from "../enums";
import { IAuthOptions } from "../interfaces";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(
        @Inject(AUTH_OPTIONS) authOptions: IAuthOptions,
        private readonly authService: AuthService,
    ) {
        super({
            usernameField: authOptions.authField === AuthField.EMAIL ? "email" : "username",
            passReqToCallback: true,
        });
    }

    // noinspection JSUnusedGlobalSymbols
    async validate(request: Request, username: string, password: string): Promise<IUserEntity> {
        return await this.authService.authenticate(username, password, request["subdomain"]);
    }
}
