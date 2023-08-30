import { IUserService } from "../interfaces";
export interface UserServiceFactoryProvider {
    imports?: any[];
    useFactory: (...args: any[]) => IUserService | Promise<IUserService>;
    inject?: any[];
}
//# sourceMappingURL=user-service-factory.provider.d.ts.map