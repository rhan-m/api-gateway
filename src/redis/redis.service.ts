import { Injectable, Inject } from '@nestjs/common';
import { Cache } from 'cache-manager';
import { CACHE_MANAGER } from '@nestjs/cache-manager';

@Injectable()
export class RedisService {
    constructor(@Inject(CACHE_MANAGER) private cacheService: Cache) { }

    async getTokens(username: string): Promise<{ accessToken: string, refreshToken: string }> | undefined {
        const accessToken = (await this.cacheService.get<string>(`${username}_accessToken`));
        const refreshToken = (await this.cacheService.get<string>(`${username}_refreshToken`));
        if (accessToken && refreshToken) {
            return { accessToken, refreshToken }
        }

        return undefined;
    }

    async setToken(username: string, token: string) {
        await this.cacheService.set(`${username}_accessToken`, token, Number(process.env.ACCESS_TOKEN));
    }

    async setTokens(username: string, accessToken: string, refreshToken: string) {
        await this.cacheService.set(`${username}_accessToken`, accessToken, Number(process.env.ACCESS_TOKEN));
        await this.cacheService.set(`${username}_refreshToken`, refreshToken, Number(process.env.REFRESH_TOKEN));
    }

}