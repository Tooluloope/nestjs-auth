import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { JwtPayload } from 'src/auth/types';

export const GetCurrentUserId = createParamDecorator(
	(_: undefined, context: ExecutionContext) => {
		const request = context.switchToHttp().getRequest();
		return request.user['sub'] as JwtPayload['sub'];
	},
);
