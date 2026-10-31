import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
const token = randomBytes(32).toString('hex');
const assets = new Map([
  ['/',{file:'web/index.html',type:'text/html; charset=utf-8'}],
  ['/app.js',{file:'web/app.js',type:'text/javascript; charset=utf-8'}],
  ['/style.css',{file:'web/style.css',type:'text/css; charset=utf-8'}],
]);
export function authenticated(value: string | undefined, secret: string): boolean {
  const candidate = Buffer.from(value ?? ''); const expected = Buffer.from('Bearer '+secret);
  return candidate.length === expected.length && timingSafeEqual(candidate,expected);
}
export const server = http.createServer({maxHeaderSize:8192,requestTimeout:5000,headersTimeout:5000},(req,res)=>{
  const send = (code:number, data:string|Buffer, type='application/json') => {
    res.writeHead(code,{'Content-Type':type,'Content-Length':Buffer.byteLength(data),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"});res.end(data);
  };
  if(!['127.0.0.1:8090','localhost:8090'].includes(req.headers.host ?? '') || req.headers.origin || req.headers['sec-fetch-site']==='cross-site') return send(403,'{"error":"Origin or host denied"}');
  if(req.method!=='GET' || req.headers['transfer-encoding'] || Number(req.headers['content-length'] ?? 0)>0) return send(405,'{"error":"Read-only API"}');
  const asset = assets.get(req.url ?? '');
  if(asset) { try { return send(200,readFileSync(asset.file),asset.type); } catch { return send(503,'{"error":"Asset unavailable"}'); } }
  if(!authenticated(req.headers.authorization,token)) return send(401,'{"error":"Management token required"}');
  if(req.url==='/api/evidence') {
    try { return send(200,readFileSync('evidence/results.json')); } catch { return send(503,'{"error":"Run evidence suite first"}'); }
  }
  return send(404,'{"error":"Not found"}');
});
if(process.argv[1]?.endsWith('server.js')) {
  server.listen(8090,process.env.BOUNTYPROOF_CONTAINER==='1'?'0.0.0.0':'127.0.0.1',()=>{
    console.log('BountyProof http://127.0.0.1:8090');
    console.log('Management token (ephemeral, paste into dashboard): '+token);
  });
}
