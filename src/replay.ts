import http from 'node:http';
const paths = new Set(['/health','/api/invoices','/sql','/xss','/ssrf','/jwt','/oauth/start','/oauth/callback','/auth/login','/auth/me','/path','/command','/business']);
export function replay(mode: string, path: string, params: Record<string,string> = {}): Promise<{status: number; body: string}> {
  if (!['fixed','vulnerable'].includes(mode) || !paths.has(path)) throw new Error('Outside owned lab scope');
  const query = new URLSearchParams(params).toString();
  return new Promise((resolve,reject) => {
    const req = http.get({hostname:'127.0.0.1',port:mode === 'fixed' ? 8092 : 8091,path:path+(query?'?'+query:''),headers:{Authorization:'Bearer fixture-alice'},timeout:3000}, res => {
      const chunks: Buffer[] = []; let size = 0;
      res.on('data',(chunk: Buffer) => { size+=chunk.length; if(size>16384) res.destroy(new Error('Response limit')); else chunks.push(chunk); });
      res.on('error',reject);
      res.on('end',()=>resolve({status:res.statusCode ?? 0,body:Buffer.concat(chunks).toString()}));
    });
    req.on('timeout',()=>req.destroy(new Error('Request timeout')));
    req.on('error',reject);
  });
}
