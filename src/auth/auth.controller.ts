import {
	Body,
	Controller,
	HttpCode,
	HttpStatus,
	Post,
	Req,
	UseGuards,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { Request } from 'express';
import { RtGuard } from './common/guards/rt.guard';
import { AtGuard } from './common/guards/at.guard';
import { GetCurrentUser } from './common/decorators/get-current-user.decorator';
import { GetCurrentUserId } from './common/decorators/get-current-user-id.decorator';
import { Public } from './common/decorators';

@Controller('auth')
export class AuthController {
	constructor(private authService: AuthService) {}

	@Public()
	@Post('local/signup')
	@HttpCode(HttpStatus.CREATED)
	signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
		return this.authService.signupLocal(dto);
	}
	@Public()
	@Post('local/signin')
	@HttpCode(HttpStatus.OK)
	signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
		return this.authService.signinLocal(dto);
	}

	@Post('logout')
	@HttpCode(HttpStatus.OK)
	logout(@GetCurrentUserId() userId: number) {
		return this.authService.logout(userId);
	}
	@Public()
	@UseGuards(RtGuard)
	@Post('refresh')
	@HttpCode(HttpStatus.OK)
	refresh(
		@GetCurrentUser('refreshToken') refreshToken: string,
		@GetCurrentUserId() userId: number,
	) {
		return this.authService.refresh(userId, refreshToken);
	}
}
