import { vercelSSO } from 'escape-sso/vercel';

export default vercelSSO();

export const config = { matcher: ['/((?!_vercel).*)'] };
