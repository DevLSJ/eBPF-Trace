"""Update the runner VM's Python collector after backend deployment, with rollback.

Preserves environment files, durable outbox, virtualenv and XDP source. Only the
verified checkout's collector package is replaced; this release has no BPF ABI change.
"""

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path
from urllib.request import urlopen


def command(*args, check=True, **kwargs):
    return subprocess.run(args, check=check, text=True, capture_output=True, **kwargs).stdout.strip()


def update(runtime, source, revision, health_url, timeout=45):
    runtime, source = Path(runtime).resolve(), Path(source).resolve()
    if len(revision) not in (40, 64) or any(char not in '0123456789abcdef' for char in revision):
        raise ValueError('A verified hexadecimal commit ID is required')
    working = command('systemctl', 'show', 'ebpf-collector.service', '-p', 'WorkingDirectory', '--value')
    if Path(working).resolve() != runtime:
        raise ValueError('Collector service WorkingDirectory differs from the deployment target')
    if not (runtime / '.env.collector').is_file() or not (runtime / 'collector').is_dir():
        raise ValueError('Existing configured collector required')
    release = runtime / '.collector-releases' / f'{revision}-{time.time_ns()}'
    stage = release / 'staging'
    package = stage / 'collector'
    package.mkdir(parents=True)
    for path in (source / 'collector').glob('*.py'):
        shutil.copy2(path, package / path.name)
    interpreter = str(runtime / '.venv-collector/bin/python')
    probe = ('from collector.feature_schema import CONTEXT_FEATURES; '
             'from collector.features import FeatureCalculator, Snapshot; '
             'f=FeatureCalculator().compute(Snapshot("192.0.2.1","192.0.2.2",1,80,6,1,60,1,0,1),1); '
             'assert f["feature_schema_version"] == 2 and all(k in f for k in CONTEXT_FEATURES)')
    command(interpreter, '-c', probe, cwd=stage)
    current, backup = runtime / 'collector', release / 'previous'
    command('sudo', '-n', 'systemctl', 'stop', 'ebpf-collector.service')
    installed = False
    try:
        current.rename(backup)
        package.rename(current)
        installed = True
        command('sudo', '-n', 'systemctl', 'start', 'ebpf-collector.service')
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                command('systemctl', 'is-active', '--quiet', 'ebpf-collector.service')
                with urlopen(health_url, timeout=3) as response:
                    health = json.load(response)
                if health.get('collector_connected') and health.get('collector_feature_schema_version') == 2:
                    print(json.dumps({'collector_revision': revision, 'feature_schema_version': 2,
                                      'rollback_package': str(backup)}))
                    return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError('Collector did not deliver version 2 observations before the deadline')
    except Exception:
        command('sudo', '-n', 'systemctl', 'stop', 'ebpf-collector.service', check=False)
        if installed:
            current.rename(release / 'failed')
        if backup.exists():
            backup.rename(current)
        command('sudo', '-n', 'systemctl', 'start', 'ebpf-collector.service')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', default='/home/ubuntu/ebpf-project')
    parser.add_argument('--source', default='.')
    parser.add_argument('--revision', required=True)
    parser.add_argument('--health-url', default='http://127.0.0.1:18000/health')
    args = parser.parse_args()
    update(args.runtime, args.source, args.revision, args.health_url)
