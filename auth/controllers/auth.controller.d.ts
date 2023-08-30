import { AuthService } from "../services/auth.service";
import { IAuthOptions } from "../interfaces";
import { LoginDto } from "../dtos";
import { Response } from "express";
import { SuccessResponse } from "hichchi-nestjs-common/responses";
import { RedisCacheService } from "hichchi-nestjs-common/cache";
import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { UpdatePasswordDto } from "../dtos/update-password.dto";
export declare class AuthController {
    private authOptions;
    private cacheService;
    private readonly authService;
    constructor(authOptions: IAuthOptions, cacheService: RedisCacheService, authService: AuthService);
    register(dto: any): Promise<IUserEntity>;
    authenticate(user: IUserEntity, _loginDto: LoginDto, response: Response): Promise<IUserEntity>;
    getCurrentUser(user: IUserEntity): Promise<IUserEntity>;
    changePassword(user: IUserEntity, updatePasswordDto: UpdatePasswordDto): Promise<IUserEntity>;
    clearAuthentication(user: IUserEntity, response: Response): Promise<SuccessResponse>;
}
//# sourceMappingURL=auth.controller.d.ts.map