import { Injectable, NestMiddleware, UnauthorizedException } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { AuthService } from './auth/auth.service';

@Injectable()
export class RequestInterceptor implements NestMiddleware {
    constructor(private readonly authService: AuthService) { }

    async use(req: Request, res: Response, next: NextFunction) {
        console.log('Incoming Request:', req.method, req.originalUrl);
        if (req.originalUrl.match('/auth/*') && req.originalUrl.match('/auth/*').length > 0 && req.method === 'POST') {
            next();
        } else {
            const validReq = await this.authService.isValidRequest(this.authService.extractToken(req.headers.authorization), req.originalUrl);
            if (validReq) {
                next();
            } else {
                throw new UnauthorizedException();
            }
        }
    }
}
