import { IUserEntity } from "hichchi-nestjs-common/interfaces";
export interface IUserService {
    createUser(userDto: Partial<IUserEntity>): Promise<IUserEntity>;
    updateUserById(id: string | number, userDto: Partial<IUserEntity>): Promise<IUserEntity>;
    getUserById(id: string | number): Promise<IUserEntity | undefined>;
    getUserByUsername(username: string): Promise<IUserEntity | undefined>;
}
//# sourceMappingURL=user-service.interface.d.ts.map