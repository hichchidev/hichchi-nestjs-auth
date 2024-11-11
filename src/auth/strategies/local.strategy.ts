import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { Inject, Injectable } from "@nestjs/common";
import { AuthService } from "../services";
import { AUTH_OPTIONS } from "../tokens";
import { AuthField } from "../enums";
import { IAuthOptions } from "../interfaces";
import { TokenUser } from "../types";
import { AuthStrategy } from "../enums/auth-strategies.enum";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, AuthStrategy.LOCAL) {
    constructor(
        @Inject(AUTH_OPTIONS) private readonly authOptions: IAuthOptions,
        private readonly authService: AuthService,
    ) {
        super({
            usernameField: authOptions.authField === AuthField.EMAIL ? "email" : "username",
            passReqToCallback: true,
        });
    }

    // noinspection JSUnusedGlobalSymbols
    async validate(request: Request, username: string, password: string): Promise<TokenUser> {
        let socketId: string;
        if (this.authOptions.socket?.idKey) {
            socketId = request.headers[this.authOptions.socket.idKey.replace("-", "").toLowerCase()];
        }
        return await this.authService.authenticate(username, password, socketId, request["subdomain"]);
    }
}
