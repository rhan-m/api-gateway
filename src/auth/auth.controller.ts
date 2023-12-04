import { Controller, HttpCode, HttpStatus, Post, UnauthorizedException, UseGuards, Res, Req } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    @HttpCode(HttpStatus.OK)
    @Post('login')
    @UseGuards(AuthGuard('basic'))
    async signIn(@Res() res: Response, @Req() req: Request) {
        try {
            const [username, _] = this.authService.extractCredentials(req.headers.authorization);
            const tokens = await this.authService.getTokens(username);
            return res.json(tokens);
        } catch (error) {
            throw new UnauthorizedException();
        }
    }

    @HttpCode(HttpStatus.OK)
    @Post('refresh')
    async refresh(@Res() res: Response, @Req() req: Request) {
        try {
            const token = this.authService.extractToken(req.headers.authorization);
            const newToken = await this.authService.refreshToken(token);
            return res.json(newToken);
        } catch (error) {
            throw new UnauthorizedException();
        }
    }
}
