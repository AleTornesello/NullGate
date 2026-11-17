#!/usr/bin/env python3
"""Install candidate packages only in an isolated disposable Debian container."""
import argparse
import json
import os
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    image=json.loads((ROOT/'packaging/release.json').read_text())['packager']
    network='nullgate-release-rehearsal-'+str(os.getpid())
    name=network+'-container'
    subprocess.run(['docker','network','create','--internal',network],check=True,stdout=subprocess.DEVNULL)
    try:
        result=subprocess.run(['docker','run','--rm','--name',name,'--platform','linux/amd64','--network',network,
            '--mount',f'type=bind,src={args.artifacts.resolve()},dst=/artifacts,readonly',
            '--mount',f'type=bind,src={ROOT},dst=/source,readonly',
            image,'sh','/source/packaging/rehearse-container.sh'],text=True,capture_output=True)
        reports=[]
        for line in result.stdout.splitlines():
            if line.startswith('{'):
                try:reports.append(json.loads(line))
                except ValueError:pass
        if result.returncode:
            # Fixtures never print tokens/passwords/keys. Keep diagnostics local, not in release files.
            print(result.stderr[-6000:])
            raise RuntimeError('Installation rehearsal failed')
        if {r.get('mode') for r in reports}!={'local','dedicated','debian-reinstall-removal'}:
            raise RuntimeError('Installation rehearsal did not run both deployment modes')
        report={'target':'x86_64-unknown-linux-gnu','runtime_image':image,'distribution':'Debian 12','profiles':reports,
                'systemd_boot_validated':False,'cross_version_upgrade_validated':False}
        args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        print(json.dumps(report))
    finally:
        subprocess.run(['docker','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)


if __name__=='__main__':main()
