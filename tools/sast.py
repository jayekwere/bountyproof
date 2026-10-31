"""Run local Semgrep rules; allow only exact reviewed vulnerable fixture sinks."""
import argparse
import ast
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {'python-shell-execution':'command_vulnerable',
            'python-sql-concatenation':'sql_vulnerable',
            'python-unescaped-html':'xss_vulnerable'}


def validate(data):
    if data.get('errors'):
        raise ValueError('Semgrep reported errors')
    source = ast.parse((ROOT/'lab/scenarios.py').read_text())
    functions = {node.name:node for node in source.body if isinstance(node,ast.FunctionDef)}
    found = set()
    for finding in data['results']:
        rule = finding['check_id'].split('.')[-1]
        name = EXPECTED.get(rule)
        node = functions.get(name)
        path = Path(finding['path'])
        if path.is_absolute():
            path = path.relative_to(ROOT)
        if (not node or path.as_posix() != 'lab/scenarios.py'
                or not node.lineno <= finding['start']['line'] <= node.end_lineno):
            raise ValueError('Unreviewed SAST result: '+str(finding))
        found.add(rule)
    if found != set(EXPECTED):
        raise ValueError('Expected vulnerable controls were not all detected: '+str(found))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--semgrep',default='semgrep')
    args = parser.parse_args()
    result = subprocess.run([args.semgrep,'scan','--config','.semgrep/rules.yml','--json','--metrics=off','--disable-version-check','lab','src','web/app.js'],cwd=ROOT,capture_output=True,text=True,timeout=120,
                            env={**os.environ,'SEMGREP_SEND_METRICS':'off'})
    if result.returncode:
        raise SystemExit(result.stderr)
    data = json.loads(result.stdout)
    validate(data)
    # Preserve scanner output; no made-up clean claim for deliberately vulnerable code.
    (ROOT/'evidence/semgrep.json').write_text(json.dumps(data,indent=2)+'\n')
    print('SAST gate passed: exactly the three reviewed vulnerable sink controls; no unreviewed results.')
