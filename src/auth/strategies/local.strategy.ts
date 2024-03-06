import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { Inject, Injectable } from "@nestjs/common";
import { AuthService } from "../services/auth.service";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { AUTH_OPTIONS } from "../tokens";
import { IAuthOptions } from "../interfaces";
import { AuthBy } from "../enums/auth-by.enum";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(
        @Inject(AUTH_OPTIONS) authOptions: IAuthOptions,
        private readonly authService: AuthService,
    ) {
        super({ usernameField: authOptions.authBy === AuthBy.EMAIL ? "email" : "username" });
    }

    // noinspection JSUnusedGlobalSymbols
    async validate(username: string, password: string): Promise<IUserEntity> {
        return await this.authService.authenticate(username, password);
    }
}
