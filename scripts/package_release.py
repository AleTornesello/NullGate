#!/usr/bin/env python3
"""Deterministic tar/deb packaging, run inside the pinned builder."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


def digest(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def archive(tree, destination, epoch):
    with open(destination, 'wb') as output:
        with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=epoch, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.GNU_FORMAT) as tar:
                for path in sorted(tree.rglob('*')):
                    if not path.is_file(): continue
                    info=tarfile.TarInfo(str(path.relative_to(tree.parent)))
                    info.size=path.stat().st_size;info.mtime=epoch;info.uid=info.gid=0
                    info.uname=info.gname='root';info.mode=0o755 if path.relative_to(tree).as_posix()=='bin/nullgate' else 0o644
                    tar.addfile(info, io.BytesIO(path.read_bytes()))


def package(binary, source, output, metadata, metadata_path):
    output.mkdir(parents=True, exist_ok=True)
    version=tomllib.loads((source/'Cargo.toml').read_text())['workspace']['package']['version']
    if metadata['target'] != 'x86_64-unknown-linux-gnu': raise ValueError('Unsupported release target')
    import struct
    header=binary.read_bytes()[:64]
    if header[:6] != b'\x7fELF\x02\x01' or struct.unpack_from('<H',header,18)[0]!=62: raise ValueError('Expected a Linux x86_64 ELF binary')
    if (metadata_path.parent/'version.txt').read_text().strip()!='nullgate '+version: raise ValueError('Binary version differs from package version')
    required=(metadata_path.parent/'elf-versions.txt').read_text()
    import re
    versions=[tuple(map(int,v.split('.'))) for v in re.findall(r'GLIBC_(\d+\.\d+(?:\.\d+)?)',required)]
    if max(versions,default=(0,)) > (2,36): raise ValueError('Artifact exceeds the glibc baseline')
    epoch=int(metadata['source_date_epoch'])
    with tempfile.TemporaryDirectory() as temp:
        tree=Path(temp)/f'nullgate-{version}-x86_64-unknown-linux-gnu'
        (tree/'bin').mkdir(parents=True);shutil.copyfile(binary,tree/'bin/nullgate');(tree/'bin/nullgate').chmod(0o755)
        for name in ['LICENSE','Cargo.lock']:
            shutil.copyfile(source/name,tree/name)
        (tree/'README.md').write_text('# NullGate '+version+'\n\nSee docs/deployment.md for verified installation, first provisioning, configuration, trust, backup and recovery commands. Run python3 install-user.py as a normal user for local installation; use the .deb for a dedicated Debian service. BUILD-MANIFEST.json is inside this bundle; verify the external SHA256SUMS alongside the downloaded tarball before extraction. No runtime state or private keys are included.\n')
        for folder in ['docs','config']:
            shutil.copytree(source/folder,tree/folder)
        shutil.copyfile(source/'packaging/install-user.py',tree/'install-user.py')
        manifest={**metadata,'builder_packages_sha256':digest(metadata_path.parent/'builder-packages.txt'),'version':version,'binary_sha256':digest(binary),'glibc_required':'.'.join(map(str,max(versions,default=(0,))))}
        (tree/'BUILD-MANIFEST.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
        # Preserve dependency notices, including vendored C-library notices, not only SPDX expressions.
        cargo=json.loads((metadata_path.parent/'cargo-metadata.json').read_text())
        notices=tree/'third-party';notices.mkdir();inventory=[]
        for entry in sorted(cargo['packages'],key=lambda p:(p['name'],p['version'])):
            if entry['source'] is None:continue
            inventory.append({'name':entry['name'],'version':entry['version'],'license':entry['license']})
            root=Path(entry['manifest_path']).parent
            for path in sorted(root.rglob('*')):
                if path.is_file() and path.name.lower().startswith(('license','licence','copying','notice','copyright')):
                    destination=notices/(entry['name']+'-'+entry['version'])/path.relative_to(root)
                    destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,destination)
        (notices/'inventory.json').write_text(json.dumps(inventory,sort_keys=True,indent=2)+'\n')
        if (metadata_path.parent/'rust-licenses').exists(): shutil.copytree(metadata_path.parent/'rust-licenses',notices/'rust-standard-library')
        archive(tree,output/(tree.name+'.tar.gz'),epoch)
        deb=Path(temp)/'deb';(deb/'DEBIAN').mkdir(parents=True)
        files={'bin/nullgate':'usr/bin/nullgate','LICENSE':'usr/share/doc/nullgate/copyright','BUILD-MANIFEST.json':'usr/share/doc/nullgate/BUILD-MANIFEST.json'}
        for a,b in files.items():
            target=deb/b;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(tree/a,target)
        (deb/'usr/bin/nullgate').chmod(0o755)
        shutil.copytree(tree/'third-party',deb/'usr/share/doc/nullgate/third-party')
        shutil.copytree(source/'docs',deb/'usr/share/doc/nullgate/guides')
        shutil.copytree(source/'config',deb/'usr/share/doc/nullgate/config')
        for a,b in [('nullgate.service','usr/lib/systemd/system/nullgate.service'),('nullgate.server.toml','etc/nullgate/nullgate.toml')]:
            target=deb/b;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/'packaging'/a,target)
        (deb/'etc/nullgate/nullgate.toml').chmod(0o640)
        for script in ['postinst','prerm','postrm']:
            shutil.copyfile(source/'packaging'/script,deb/'DEBIAN'/script);(deb/'DEBIAN'/script).chmod(0o755)
        (deb/'DEBIAN/conffiles').write_text('/etc/nullgate/nullgate.toml\n')
        (deb/'DEBIAN/control').write_text(f'Package: nullgate\nVersion: {version}\nArchitecture: amd64\nMaintainer: NullGate contributors\nDepends: libc6 (>= 2.36), libgcc-s1, ca-certificates, passwd\nSection: net\nPriority: optional\nDescription: Shared DNS and explicit HTTP/HTTPS filtering proxy\n')
        for p in sorted(deb.rglob('*'),reverse=True):
            relative=p.relative_to(deb).as_posix()
            mode=0o755 if p.is_dir() or relative in ['usr/bin/nullgate','DEBIAN/postinst','DEBIAN/prerm','DEBIAN/postrm'] else 0o644
            if relative=='etc/nullgate/nullgate.toml':mode=0o640
            p.chmod(mode);os.utime(p,(epoch,epoch),follow_symlinks=False)
        deb.chmod(0o755)
        os.utime(deb,(epoch,epoch))
        subprocess.run(['dpkg-deb','--root-owner-group','--threads-max=1','-Zgzip','-z9','--build',str(deb),str(output/f'nullgate_{version}_amd64.deb')],check=True)
        shutil.copyfile(tree/'BUILD-MANIFEST.json',output/'BUILD-MANIFEST.json')
    names=sorted(p.name for p in output.iterdir() if p.is_file() and p.name!='SHA256SUMS')
    (output/'SHA256SUMS').write_text(''.join(digest(output/name)+'  '+name+'\n' for name in names))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ['binary','source','output','metadata']:parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();package(args.binary,args.source,args.output,json.loads(args.metadata.read_text()),args.metadata)
