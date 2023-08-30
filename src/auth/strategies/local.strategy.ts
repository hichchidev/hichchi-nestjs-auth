import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { Injectable } from "@nestjs/common";
import { AuthService } from "../services/auth.service";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(private readonly authService: AuthService) {
        super({ usernameField: "username" });
    }

    // noinspection JSUnusedGlobalSymbols
    async validate(username: string, password: string): Promise<IUserEntity> {
        return await this.authService.authenticate(username, password);
    }
}
