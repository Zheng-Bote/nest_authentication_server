import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserModule } from './user/user.module';
import { ResetModule } from './reset/reset.module';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: '192.168.1.65',
      port: 6543,
      username: 'auth_user',
      password: 'auth_user',
      database: 'nest_auth',
      autoLoadEntities: true,
      synchronize: true,
    }),
    UserModule,
    ResetModule,
  ],
})
export class AppModule {}
