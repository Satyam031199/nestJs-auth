import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthGuard } from './guards/auth.guard';
import { AuthorizationGuard } from './guards/authorization.guard';
import { Role } from './decorators/roles.decorators';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Role('admin')
  @UseGuards(AuthGuard,AuthorizationGuard)
  @Get()
  someProtectedRoute(@Req() request){
    return {message: 'Accessed Resource',userId: request.userId}
  }
}
