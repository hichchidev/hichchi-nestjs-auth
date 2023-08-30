import { IUserService } from "../interfaces";
export interface UserServiceExistingProvider {
    imports?: any[];
    useExisting: new (...args: any[]) => IUserService;
}
//# sourceMappingURL=user-service-existing.provider.d.ts.map