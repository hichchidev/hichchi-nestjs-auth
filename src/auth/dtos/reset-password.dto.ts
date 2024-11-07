import { IsNotEmpty } from "class-validator";

export class ResetPasswordDto {
    @IsNotEmpty()
    token: string;

    @IsNotEmpty()
    password: string;
}
