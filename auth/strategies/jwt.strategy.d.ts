import { Strategy } from "passport-jwt";
import { IAuthOptions, ITokenData, IUserService } from "../interfaces";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
declare const JwtStrategy_base: new (...args: any[]) => Strategy;
export declare class JwtStrategy extends JwtStrategy_base {
    private userService;
    constructor(userService: IUserService, authOptions: IAuthOptions);
    validate(jwtPayload: ITokenData): Promise<IUserEntity>;
}
export {};
//# sourceMappingURL=jwt.strategy.d.ts.map