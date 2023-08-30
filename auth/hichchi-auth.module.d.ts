import { DynamicModule } from "@nestjs/common";
import { UserServiceFactoryProvider, UserServiceExistingProvider } from "./providers";
import { IAuthOptions } from "./interfaces";
export declare const DEFAULT_SECRET = "3cGnEj4Kd1ENr8UcX8fBKugmv7lXmZyJtsa_fo-RcIk";
export declare class HichchiAuthModule {
    static registerAsync(userServiceProvider: UserServiceFactoryProvider | UserServiceExistingProvider, authOptions: IAuthOptions): DynamicModule;
}
//# sourceMappingURL=hichchi-auth.module.d.ts.map