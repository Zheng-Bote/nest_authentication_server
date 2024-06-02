import {
  BadRequestException,
  Body,
  Controller,
  Post,
  Get,
  Res,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import { UserService } from './user.service';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { Response, Request } from 'express';
import { TokenService } from './token.service';
import { MoreThanOrEqual } from 'typeorm';

@Controller()
export class UserController {
  constructor(
    private userService: UserService,
    private jwtService: JwtService,
    private tokenService: TokenService,
  ) {}
  @Post('register')
  async register(@Body() body: any) {
    if (body.password !== body.password_confirm) {
      throw new BadRequestException('Password do not match!');
    }
    return this.userService.save({
      first_name: body.first_name,
      last_name: body.last_name,
      email: body.email,
      password: await bcryptjs.hash(body.password, 12),
    });
  }

  @Post('login')
  async login(
    @Body('email') email: string,
    @Body('password') password: string,
    @Res({ passthrough: true }) response: Response,
  ) {
    const user = await this.userService.findOne({ where: { email } });

    if (!user) {
      throw new BadRequestException('invalid credentials');
    }

    if (!(await bcryptjs.compare(password, user.password))) {
      throw new BadRequestException('invalid credentials');
    }

    const accessToken = await this.jwtService.signAsync(
      { id: user.id },
      { expiresIn: '30s' },
    );

    const expired_at = new Date();
    expired_at.setDate(expired_at.getDate() + 7);

    const refreshToken = await this.jwtService.signAsync({ id: user.id });

    await this.tokenService.save({
      user_id: user.id,
      token: refreshToken,
      expired_at,
    });

    response.status(200);
    response.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      maxAge: 7 * 24 * 68 * 60 * 1000, // 1 week
    });

    return { token: accessToken };
  }

  @Get('user')
  async user(@Req() request: Request) {
    try {
      const accessToken = request.headers.authorization.replace('Bearer ', '');
      const { id } = await this.jwtService.verifyAsync(accessToken);

      const { password, ...data } = await this.userService.findOne({
        where: { id },
      });

      return data;
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  @Post('refresh')
  async refresh(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    try {
      const refreshToken = request.cookies['refresh_token'];
      const { id } = await this.jwtService.verifyAsync(refreshToken);

      const tokenEntity = await this.tokenService.findOne({
        where: {
          user_id: id,
          expired_at: MoreThanOrEqual(new Date()),
        },
      });

      if (!tokenEntity) {
        throw new UnauthorizedException('no token');
      }

      const accessToken = await this.jwtService.signAsync(
        { id },
        { expiresIn: '30s' },
      );

      response.status(200);
      return { token: accessToken };
    } catch (error) {
      throw new UnauthorizedException('doof');
    }
  }

  @Post('logout')
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    await this.tokenService.delete({ token: request.cookies['refresh_token'] });

    response.clearCookie('refresh_token');

    return { message: 'success' };
  }
}
