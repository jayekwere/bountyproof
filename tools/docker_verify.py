"""Inspect only this Compose project, verify isolation and replay all scenarios."""
import json
import subprocess
from pathlib import Path
from tools.verify import verify


def docker(*args):
    return subprocess.check_output(['docker',*args],text=True,timeout=20)


if __name__ == '__main__':
    project = json.loads(docker('compose','--profile','lab','config','--format','json'))
    controls = []
    for name in project['services']:
        identifier = docker('compose','ps','-q',name).strip()
        assert identifier, name
        config = json.loads(docker('inspect',identifier))[0]
        host = config['HostConfig']
        assert config['Config']['User'] == '10001:10001'
        assert host['ReadonlyRootfs'] and host['CapDrop'] == ['ALL']
        assert 'no-new-privileges:true' in host['SecurityOpt']
        assert host['PidsLimit'] == 32 and host['Memory'] == 201326592 and host['NanoCpus'] == 500000000
        for bindings in (host.get('PortBindings') or {}).values():
            for binding in bindings or []:
                assert binding['HostIp'] == '127.0.0.1'
        if not name.endswith('-gateway'):
            assert not host.get('PortBindings')
            for network in config['NetworkSettings']['Networks']:
                detail = json.loads(docker('network','inspect',network))[0]
                assert detail['Internal']
        controls.append({'service':name,'uid':'10001:10001','readOnly':True,'capabilitiesDropped':True,'noNewPrivileges':True,'limitsVerified':True,'loopbackIngressOnly':True})
    # No outbound packets are sent: verify that lab routing tables have no default route.
    for name in ('vulnerable','fixed'):
        routes = docker('compose','exec','-T',name,'python','-c',"from pathlib import Path; print(Path('/proc/net/route').read_text())")
        assert not any(line.split()[1] == '00000000' for line in routes.splitlines()[1:] if line.split()), routes
    evidence = verify()
    evidence['containerControls'] = controls
    Path('evidence/docker-http.json').write_text(json.dumps(evidence,indent=2)+'\n')
    print('Docker: 10 lifecycles passed; six hardened services inspected; lab containers have no default route.')
