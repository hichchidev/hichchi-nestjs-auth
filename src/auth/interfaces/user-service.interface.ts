import { IUserEntity } from "hichchi-nestjs-common/interfaces";

export interface IUserService {
    registerUser(userDto: Partial<IUserEntity>): Promise<IUserEntity>;
    updateUserById(id: string | number, userDto: Partial<IUserEntity>, updatedBy: IUserEntity): Promise<IUserEntity>;
    getUserById(id: string | number, subdomain?: string): Promise<IUserEntity | undefined>;
    getUserByUsername?(username: string, subdomain?: string): Promise<IUserEntity | undefined>;
    getUserByEmail?(email: string, subdomain?: string): Promise<IUserEntity | undefined>;
    getUserByUsernameOrEmail?(username: string, subdomain?: string): Promise<IUserEntity | undefined>;
}
