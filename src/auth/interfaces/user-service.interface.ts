import { IUserEntity } from "hichchi-nestjs-common/interfaces";
import { Request } from "express";
import { TokenUser } from "../types";

export interface IUserService {
    registerUser(userDto: Partial<IUserEntity>): Promise<IUserEntity>;
    updateUserById(id: string | number, userDto: Partial<IUserEntity>, updatedBy: IUserEntity): Promise<IUserEntity>;
    getUserById(id: string | number, subdomain?: string): Promise<IUserEntity | undefined>;
    getUserByUsername?(username: string, subdomain?: string): Promise<IUserEntity | undefined>;
    getUserByEmail?(email: string, subdomain?: string): Promise<IUserEntity | undefined>;
    getUserByUsernameOrEmail?(username: string, subdomain?: string): Promise<IUserEntity | undefined>;
    sendPasswordResetEmail?(email: string, token: string | number, subdomain?: string): Promise<boolean>;

    // Events
    onRegister?(request: Request, userId: string | number): Promise<void>;
    onLogin?(request: Request, tokenUser?: TokenUser, error?: Error): Promise<void>;
    onRefreshTokens?(request: Request, tokenUser?: TokenUser): Promise<void>;
    onGetCurrentUser?(request: Request, tokenUser?: TokenUser, error?: Error): Promise<void>;
    onChangePassword?(request: Request, tokenUser?: TokenUser, error?: Error): Promise<void>;
    onRequestPasswordReset?(request: Request, userId?: string | number): Promise<void>;
    onVerifyResetPasswordToken?(request: Request, userId?: string | number): Promise<void>;
    onResetPassword?(request: Request, userId?: string | number): Promise<void>;
    onLogout?(request: Request, tokenUser?: TokenUser, error?: Error): Promise<void>;
}
