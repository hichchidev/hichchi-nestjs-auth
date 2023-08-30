import { IUserEntity } from "./user-entity.interface";

export interface IUserService {
    createUser(userDto: Partial<IUserEntity>): Promise<IUserEntity>;
    getUserById(id: string | number): Promise<IUserEntity | undefined>;
    getUserByUsername(username: string): Promise<IUserEntity | undefined>;
}
