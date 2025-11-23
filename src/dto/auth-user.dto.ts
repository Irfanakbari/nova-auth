import { IsString, IsOptional, IsArray, ArrayNotEmpty } from 'class-validator';

export class AuthUserDto {
  @IsString()
  sub!: string;

  @IsString()
  name!: string;

  @IsString()
  username!: string;

  @IsOptional()
  @IsString()
  email?: string;

  @IsOptional()
  @IsString()
  sessionId?: string;

  @IsArray()
  @ArrayNotEmpty()
  role!: string[];

  @IsOptional()
  @IsString()
  azureId?: string;
}
