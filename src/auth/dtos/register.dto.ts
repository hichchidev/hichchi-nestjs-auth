import { IsNotEmpty, ValidateIf } from "class-validator";
import { IRegisterDto } from "../interfaces";
import { toErrString } from "hichchi-nestjs-common/converters";
import { AuthErrors } from "../responses";

export class RegisterDto implements IRegisterDto {
    @IsNotEmpty(toErrString(AuthErrors.AUTH_400_EMPTY_UNAME_EMAIL))
    @ValidateIf(({ email }) => !email)
    username?: string;

    @IsNotEmpty(toErrString(AuthErrors.AUTH_400_EMPTY_UNAME_EMAIL))
    @ValidateIf(({ username }) => !username)
    email?: string;

    @IsNotEmpty(toErrString(AuthErrors.AUTH_400_EMPTY_PASSWORD))
    password: string;
}
