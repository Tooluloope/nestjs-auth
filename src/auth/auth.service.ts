import { ForbiddenException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import * as argon2 from 'argon2';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './types';

@Injectable()
export class AuthService {
	constructor(private prisma: PrismaService, private jwtService: JwtService) {}

	async updateRTHash(userId: number, rt: string) {
		const hashedRt = await this.hashData(rt);
		await this.prisma.user.update({
			where: {
				id: userId,
			},
			data: {
				hashedRt,
			},
		});
	}
	async signupLocal({ password, email }: AuthDto): Promise<Tokens> {
		try {
			const hash = await this.hashData(password);

			const newUser = await this.prisma.user.create({
				data: {
					email,
					hash,
				},
			});
			const tokens = await this.getTokens(newUser.id, newUser.email);
			await this.updateRTHash(newUser.id, tokens.refresh_token);
			return tokens;
		} catch (error) {
			if (error instanceof PrismaClientKnownRequestError) {
				if (error.code === 'P2002') {
					throw new ForbiddenException('Credentials incorrect or exist');
				}
			}
			throw error;
		}
	}

	async signinLocal({ password, email }: AuthDto) {
		const user = await this.prisma.user.findUnique({
			where: {
				email: email,
			},
		});
		if (!user) throw new ForbiddenException('Access Denied');
		if (!user.hash) throw new ForbiddenException('Access Denied');
		const passwordMatches = await argon2.verify(user.hash, password);
		if (!passwordMatches) throw new ForbiddenException('Access Denied');
		const tokens = await this.getTokens(user.id, user.email);
		await this.updateRTHash(user.id, tokens.refresh_token);
		return tokens;
	}

	async logout(userId: number) {
		await this.prisma.user.updateMany({
			where: {
				id: userId,
				hashedRt: {
					not: null,
				},
			},
			data: {
				hashedRt: null,
			},
		});
	}

	async refresh(userId: number, refreshToken: string) {
		const user = await this.prisma.user.findUnique({
			where: {
				id: userId,
			},
		});
		if (!user) throw new ForbiddenException('Access Denied');
		if (!user.hashedRt) throw new ForbiddenException('Access Denied');
		const refreshMatches = await argon2.verify(user.hashedRt, refreshToken);
		if (!refreshMatches) throw new ForbiddenException('Access Denied');
		const tokens = await this.getTokens(user.id, user.email);
		await this.updateRTHash(user.id, tokens.refresh_token);
		return tokens;
	}

	async hashData(data: string) {
		return argon2.hash(data, { saltLength: 10 });
	}
	async getTokens(userId: number, email: string) {
		const [access_token, refresh_token] = await Promise.all([
			this.jwtService.signAsync(
				{
					sub: userId,
					email,
				},
				{
					expiresIn: '15m',
					secret: 'at-secret',
				},
			),
			this.jwtService.signAsync(
				{
					sub: userId,
					email,
				},
				{
					expiresIn: '7d',
					secret: 'rt-secret',
				},
			),
		]);
		return {
			access_token,
			refresh_token,
		};
	}
}
