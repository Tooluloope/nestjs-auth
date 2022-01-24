import { PrismaModule } from './../prisma/prisma.module';
import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { APP_GUARD } from '@nestjs/core';
import { AtGuard } from '../auth/common/guards/at.guard';
import { ConfigModule } from '@nestjs/config';

@Module({
	imports: [ConfigModule.forRoot({ isGlobal: true }), AuthModule, PrismaModule],
	providers: [
		{
			provide: APP_GUARD,
			useClass: AtGuard,
		},
	],
})
export class AppModule {}
