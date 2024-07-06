import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './model/User';
import { RefreshToken, RefreshTokenSchema } from './model/RefreshToken';
import { ResetToken, ResetTokenSchema } from './model/ResetToken';
import { MailService } from 'src/services/mail.service';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: RefreshToken.name, schema: RefreshTokenSchema },
      { name: ResetToken.name, schema: ResetTokenSchema}
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService,MailService],
})
export class AuthModule {}
