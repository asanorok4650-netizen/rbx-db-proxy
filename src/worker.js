// Workerの入口。/auth/ はログイン処理(auth.js)、それ以外は従来のプロキシ(index.js)に任せる。
import base from './index.js';
import { handleAuth } from './auth.js';

export default {
  async fetch(req, env, ctx) {
    if (new URL(req.url).pathname.startsWith('/auth/')) return handleAuth(req, env, ctx);
    return base.fetch(req, env, ctx);
  },
};
