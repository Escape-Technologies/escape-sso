import { createServer } from 'node:http';
import { nodeSSO } from 'escape-sso/node';

const app = (req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end(`Hello ${req.ssoUser?.email}`);
};
createServer(nodeSSO(app)).listen(3000);
