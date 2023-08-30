import { IsNotEmpty, IsString } from "class-validator";
import { ILoginDto } from "../interfaces";

export class LoginDto implements ILoginDto {
    @IsString()
    @IsNotEmpty()
    username: string;

    @IsString()
    @IsNotEmpty()
    password: string;
}
