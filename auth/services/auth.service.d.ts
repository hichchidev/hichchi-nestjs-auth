import { IAuthOptions, IRegisterDto, ITokenResponse, IUserService, ITokenData } from "../interfaces";
import { JwtService } from "@nestjs/jwt";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { UpdatePasswordDto } from "../dtos/update-password.dto";
export declare class AuthService {
    private userService;
    private authOptions;
    private readonly jwtService;
    constructor(userService: IUserService, authOptions: IAuthOptions, jwtService: JwtService);
    static generateRandomHash(): string;
    static generatePassword(password: string): {
        salt: string;
        password: string;
    };
    static verifyHash(password: string, hash: string, salt: string): boolean;
    generateToken(payload: ITokenData, secret: string, expiresIn: number): string;
    register(registerDto: IRegisterDto): Promise<IUserEntity>;
    authenticate(username: string, password: string): Promise<IUserEntity>;
    getCurrentUser(id: number): Promise<IUserEntity>;
    changePassword(id: number, updatePasswordDto: UpdatePasswordDto): Promise<IUserEntity>;
    generateTokens(user: IUserEntity): ITokenResponse;
    verifyToken(token: string, refresh?: boolean): {
        sub: number;
        email: number;
    };
    getUserByToken(bearerToken: string, refresh?: boolean): Promise<IUserEntity>;
}
//# sourceMappingURL=auth.service.d.ts.map