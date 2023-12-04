import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { UserService } from './user.service';
import { PrismaService } from './prisma/prisma.service';
import { AuthModule } from './auth/auth.module';
import { AuthController } from './auth/auth.controller';
import { RequestInterceptor } from './request.interceptor';

@Module({
	imports: [AuthModule],
	controllers: [AuthController],
	providers: [UserService, PrismaService],
})

export class AppModule implements NestModule {
	configure(consumer: MiddlewareConsumer) {
	  consumer.apply(RequestInterceptor).forRoutes('*');
	}
}
