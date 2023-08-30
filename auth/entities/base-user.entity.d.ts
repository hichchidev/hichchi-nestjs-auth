import { IUserEntity } from "hichchi-nestjs-common/interfaces";
export declare class BaseUserEntity implements IUserEntity {
    id: any;
    username: string;
    password: string;
    salt: string;
    role?: string;
}
//# sourceMappingURL=base-user.entity.d.ts.map