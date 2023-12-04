import { Injectable, UnauthorizedException } from '@nestjs/common';
import { UserService } from 'src/user.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { PassportStrategy } from '@nestjs/passport';
import { BasicStrategy } from 'passport-http';
import { RedisService } from 'src/redis/redis.service';

@Injectable()
export class AuthService extends PassportStrategy(BasicStrategy) {
    constructor(
        private readonly userService: UserService,
        private readonly jwtService: JwtService,
        private readonly redisService: RedisService
    ) {
        super();
    }

    extractCredentials(authorization: string): string[] {
        const base64Credentials = authorization.split(' ')[1];
        const credentials = Buffer.from(base64Credentials, 'base64').toString('utf-8');
        return credentials.split(':');
    }

    extractToken(authorization: string): string {
        if (authorization.includes("Bearer")) {
            return authorization.replace("Bearer ", "");
        }
        throw new UnauthorizedException();
    }

    async getTokens(username: string): Promise<{ accessToken: string, refreshToken: string }> | undefined {
        return await this.redisService.getTokens(username);
    }

    async refreshToken(refreshToken: string): Promise<string> | undefined {
        const userInfo = await this.jwtService.decode(refreshToken);
        if (userInfo.exp && userInfo.exp > Math.floor(Date.now() / 1000)) {
            const accessTokenPayload = { userId: userInfo.id, user: userInfo.username };
            const accessToken = await this.jwtService.signAsync(accessTokenPayload, { expiresIn: process.env.ACCESS_TOKEN_TTL });

            await this.redisService.setToken(userInfo.username, accessToken);
            return accessToken;
        }
        throw new UnauthorizedException();
    }

    async validate(username: string, password: string): Promise<{ accessToken: string, refreshToken: string }> | undefined {
        const user = await this.userService.user(username);
        if (user !== null && user.active) {
            const passwordsMatch: boolean = await bcrypt.compare(password, user.password);

            if (!passwordsMatch) {
                throw new UnauthorizedException();
            }
            const accessTokenPayload = { userId: user.id, user: username };
            const refreshTokenPayload = { userId: user.id, user: username };

            const accessToken = await this.jwtService.signAsync(accessTokenPayload, { expiresIn: process.env.ACCESS_TOKEN_TTL });
            const refreshToken = await this.jwtService.signAsync(refreshTokenPayload, { expiresIn: process.env.REFRESH_TOKEN_TTL });

            await this.redisService.setTokens(username, accessToken, refreshToken);
            return {
                accessToken, refreshToken
            };
        } else {
            throw new UnauthorizedException();
        }
    }

    async isValidRequest(token: string, path: string): Promise<boolean> {
        const userInfo = await this.jwtService.decode(token);
        return userInfo && userInfo.exp > Math.floor(Date.now() / 1000);
    }
}
