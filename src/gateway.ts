/** Fixed upstream gateway. Only this small process has a published network. */
import http from 'node:http';
const routes: Record<string,{host:string;port:number}> = {
  dashboard:{host:'dashboard',port:8090},vulnerable:{host:'vulnerable',port:8091},fixed:{host:'fixed',port:8092}
};
const route=routes[process.env.SERVICE ?? ''];
if(!route)throw new Error('Unknown fixed gateway service');
http.createServer({maxHeaderSize:8192,requestTimeout:5000,headersTimeout:5000},(req,res)=>{
  if(req.method!=='GET'||Number(req.headers['content-length']??0)>0||req.headers['transfer-encoding']||!req.url?.startsWith('/')||req.url.startsWith('//')||req.url.length>4096){res.writeHead(405);res.end();return;}
  const upstream=http.request({host:route.host,port:route.port,path:req.url,method:'GET',headers:req.headers,timeout:3000},response=>{
    res.writeHead(response.statusCode??502,response.headers);response.pipe(res);
  });
  upstream.on('timeout',()=>upstream.destroy(new Error('Upstream timeout')));
  upstream.on('error',()=>{if(!res.headersSent)res.writeHead(502);res.end();});
  req.on('aborted',()=>upstream.destroy());upstream.end();
}).listen(route.port,'0.0.0.0');
