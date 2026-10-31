"""Export original lab findings to Markdown reports, preserving raw HTTP evidence."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def report(item, generated):
    sections = [f"# {item['id']}: {item['title']}",
                f"Educational local fixture finding. Severity: {item['severity']}. {item['cwe']}; {item['owasp']}.",
                f"Evidence collected: {generated}",
                '## Scope\nOwned local lab only. Fictional identities and data. No third-party disclosure or bounty claim.',
                '## Root cause\n'+item['rootCause'], '## Impact\n'+item['impact'],
                '## Reproduction\nStart `python3 -m tools.lab`. Replay the exact request below against port 8091, then port 8092. Use `python3 -m tools.verify` to assert the entire lifecycle.']
    responses = [('Vulnerable evidence',item['before']),('Remediation evidence',item['after']),('Legitimate operation',item['positive'])]
    responses += [(f'Additional regression evidence {index}',value) for index,value in enumerate(item['additional'],1)]
    for label,response in responses:
        sections.append('## '+label+'\n```http\n'+response['request']+'\r\n\r\nHTTP/1.1 '+str(response['status'])+'\r\n'+'\r\n'.join(k+': '+v for k,v in response['headers'].items())+'\r\n\r\n'+response['body']+'\n```')
    sections += ['## Vulnerable code\n```python\n'+item['vulnerableCode']+'```',
                 '## Corrected code\n```python\n'+item['fixedCode']+'```',
                 '## Regression result\nReproduction, remediation, and legitimate access assertions passed over HTTP. XSS script execution additionally requires the Playwright suite.',
                 '## Limitations\n'+item['limitation'],
                 '## Learning references\n'+item['reference']+'\n\n'+item['labs']+'\n\nNo PortSwigger lab completion claimed.']
    return ('\n\n'.join(sections)+'\n').replace('\r\n','\n')

if __name__ == '__main__':
    data = json.loads((ROOT/'evidence/results.json').read_text())
    for item in data['findings']:
        (ROOT/'reports'/f"{item['id']}-{item['slug']}.md").write_text(report(item,data['generatedAt']))
    print('Exported ten professional research reports.')
