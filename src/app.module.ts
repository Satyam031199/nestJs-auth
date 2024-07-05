import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [MongooseModule.forRoot('mongodb+srv://satyam-chaturvedi:satyam-chaturvedi@satyamcluster.yvb6qzy.mongodb.net/jwt-nest?retryWrites=true'),
    AuthModule,
    JwtModule.register({global: true, secret: 'JwtSecret123'})  
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
