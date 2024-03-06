import { IsNotEmpty, IsString, ValidateIf } from "class-validator";
import { ILoginDto } from "../interfaces";
import { toErrString } from "hichchi-nestjs-common/converters";
import { AuthErrors } from "../responses";

export class LoginDto implements ILoginDto {
    @IsNotEmpty(toErrString(AuthErrors.AUTH_400_EMPTY_UNAME_EMAIL))
    @ValidateIf(({ email }) => !email)
    username?: string;

    @IsNotEmpty(toErrString(AuthErrors.AUTH_400_EMPTY_UNAME_EMAIL))
    @ValidateIf(({ username }) => !username)
    email?: string;

    @IsString()
    @IsNotEmpty()
    password: string;
}
