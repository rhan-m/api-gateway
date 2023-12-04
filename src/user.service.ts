import { Injectable } from '@nestjs/common';
import { PrismaService } from './prisma/prisma.service';
import { User } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const SALT_ROUNDS = process.env.SALT_ROUNDS;

@Injectable()
export class UserService {
	constructor(private prisma: PrismaService) { }

	async users(): Promise<User[] | null> {
		return await this.prisma.$queryRaw`SELECT * FROM "User"`;
	}

	async user(name: string): Promise<User | null> {
		return await this.prisma.user.findFirst({
			where: {
				username: name,
			},
		});
	}

	async createUser(username: string, password: string, name: string): Promise<User> {
		return await this.prisma.$queryRaw`INSERT INTO "User"(username, name, password, created_at) VALUES (${username}, ${name}, ${bcrypt.hash(password, SALT_ROUNDS)}, ${new Date().getTime()})`;
	}
}