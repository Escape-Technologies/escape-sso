import { withSSO } from 'escape-sso/fetch';

export default {
  fetch: withSSO(async (request, env, ctx) => {
    return new Response(`Hello ${String(env.APP_NAME ?? 'there')}`);
  }),
};
