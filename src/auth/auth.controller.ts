import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDTO } from './dto/createUser.dto';
import { LoginUserDTO } from './dto/loginUser.dto';
import { RefreshTokenDTO } from './dto/refreshToken.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body() userDetails: CreateUserDTO){
    return this.authService.signup(userDetails);
  }

  @Post('login')
  async login(@Body() userDetails: LoginUserDTO){
    return this.authService.login(userDetails);
  }

  @Post('refresh')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDTO){
    return this.authService.refreshTokens(refreshTokenDto.refreshToken);
  }
}
