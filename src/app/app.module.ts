import { PrismaModule } from './../prisma/prisma.module';
import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';

@Module({
	imports: [AuthModule, PrismaModule],
	controllers: [],
})
export class AppModule {}
