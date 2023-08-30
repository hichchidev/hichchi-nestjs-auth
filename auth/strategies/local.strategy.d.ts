import { Strategy } from "passport-local";
import { AuthService } from "../services/auth.service";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
declare const LocalStrategy_base: new (...args: any[]) => Strategy;
export declare class LocalStrategy extends LocalStrategy_base {
    private readonly authService;
    constructor(authService: AuthService);
    validate(username: string, password: string): Promise<IUserEntity>;
}
export {};
//# sourceMappingURL=local.strategy.d.ts.map