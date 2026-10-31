import { readFileSync } from 'node:fs';
import { replay } from './replay.js';
const [mode='fixed', scenario='idor'] = process.argv.slice(2);
const evidence: unknown = JSON.parse(readFileSync('evidence/results.json','utf8'));
if(typeof evidence !== 'object' || !evidence || !('findings' in evidence) || !Array.isArray(evidence.findings)) throw new Error('Invalid evidence');
const finding = evidence.findings.find((item: {slug:string})=>item.slug===scenario) as {path:string;attack:Record<string,string>} | undefined;
if(!finding) throw new Error('Choose one of the ten included scenario slugs.');
console.log(JSON.stringify(await replay(mode,finding.path,finding.attack),null,2));
