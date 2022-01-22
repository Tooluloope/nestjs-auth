import { Body, Controller, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
	constructor(private authService: AuthService) {}
	@Post('local/signup')
	@HttpCode(HttpStatus.CREATED)
	signupLocal(@Body() dto: AuthDto): Promise<Tokens> {
		return this.authService.signupLocal(dto);
	}

	@Post('local/signin')
	@HttpCode(HttpStatus.OK)
	signinLocal(@Body() dto: AuthDto): Promise<Tokens> {
		return this.authService.signinLocal(dto);
	}

	@Post('logout')
	@HttpCode(HttpStatus.OK)
	logout() {
		// return this.authService.logout();
	}

	@Post('refresh')
	@HttpCode(HttpStatus.OK)
	refresh() {
		return this.authService.refresh();
	}
}
