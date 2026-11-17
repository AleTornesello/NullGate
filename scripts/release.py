#!/usr/bin/env python3
"""Build candidate artifacts in a pinned Linux amd64 container; never publish or tag."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from verify_test_run import summarize

ROOT=Path(__file__).resolve().parents[1]


def inputs():
    names=['Cargo.toml','Cargo.lock','rust-toolchain.toml','README.md','LICENSE']
    guides={'administration.md','deployment.md','filtering-rules.md','architecture.md','system-verification.md','implementation-decisions.md'}
    for folder in ['crates','config','docs','packaging','scripts']:
        for p in (ROOT/folder).rglob('*'):
            if not p.is_file() or any(part in ['target','__pycache__','inspection-ca'] for part in p.relative_to(ROOT).parts):continue
            if folder=='crates' and not (p.suffix in ['.rs','.css','.js'] or p.name=='Cargo.toml'):continue
            if folder=='docs' and (p.parent!=ROOT/'docs' or p.name not in guides):continue
            if folder=='config' and p.name not in ['nullgate.example.toml','nullgate.oidc.example.toml']:continue
            if folder=='scripts' and p.suffix!='.py':continue
            names.append(str(p.relative_to(ROOT)))
    return sorted(set(names))


def fingerprint(names):
    checksum=hashlib.sha256()
    for name in names:
        path=ROOT/name
        if path.is_symlink():raise ValueError('Release inputs must not be symlinks')
        checksum.update(name.encode()+b'\0'+path.read_bytes()+b'\0')
    return checksum.hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--reproduce',action='store_true')
    parser.add_argument('--require-clean',action='store_true')
    args=parser.parse_args();output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    settings=json.loads((ROOT/'packaging/release.json').read_text())
    import tomllib
    if tomllib.loads((ROOT/'rust-toolchain.toml').read_text())['toolchain']['channel']!=settings['rust']:parser.error('Compiler pin differs from rust-toolchain.toml')
    dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT))
    if args.require_clean and dirty:parser.error('Release workflow requires a clean checkout')
    names=inputs()
    metadata={**settings,'source_date_epoch':int(os.environ.get('SOURCE_DATE_EPOCH') or subprocess.check_output(['git','log','-1','--format=%ct'],cwd=ROOT,text=True).strip()),
              'git_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'dirty':dirty,'input_tree_sha256':fingerprint(names)}
    cache=Path(os.environ.get('CARGO_HOME',Path.home()/'.cargo'))/'registry'
    if not cache.is_dir():parser.error('Populate the Cargo registry with cargo fetch --locked first')
    previous=None
    for iteration in range(2 if args.reproduce else 1):
        work=output/f'work-{iteration}';work.mkdir(exist_ok=False)
        source=work/'source';source.mkdir()
        for name in names:
            destination=source/name;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/name,destination)
        result=work/'result';result.mkdir();(result/'input.json').write_text(json.dumps(metadata,sort_keys=True))
        command=['docker','run','--rm','--platform','linux/amd64','--env','SOURCE_DATE_EPOCH='+str(metadata['source_date_epoch']),
                 '--network','none','--env','BUILD_UID='+str(os.getuid()),'--env','BUILD_GID='+str(os.getgid()),
                 '--mount',f'type=bind,src={source},dst=/src,readonly',
                 '--mount',f'type=bind,src={result},dst=/out',
                 '--mount',f'type=bind,src={cache.resolve()},dst=/usr/local/cargo/registry']
        command += [settings['builder'],'sh','/src/packaging/build-in-container.sh']
        subprocess.run(command,check=True)
        e2e=summarize('Running tests/end_to_end.rs\n'+(result/'e2e-results.txt').read_text())
        (result/'e2e-summary.json').write_text(json.dumps(e2e,sort_keys=True)+'\n')
        if not e2e['guard_ok']:raise RuntimeError('Packaged executable failed nonzero behavioral coverage guard')
        command=['docker','run','--rm','--network','none','--platform','linux/amd64',
                 '--env','SOURCE_DATE_EPOCH='+str(metadata['source_date_epoch']),
                 '--user',str(os.getuid())+':'+str(os.getgid()),
                 '--mount',f'type=bind,src={source},dst=/src,readonly',
                 '--mount',f'type=bind,src={result},dst=/out',
                 '--mount',f'type=bind,src={cache.resolve()},dst=/usr/local/cargo/registry,readonly',
                 settings['packager'],'python3','/src/scripts/package_release.py','--binary','/out/nullgate','--source','/src','--output','/out/artifacts','--metadata','/out/input.json']
        subprocess.run(command,check=True)
        artifacts=result/'artifacts'
        manifest=(artifacts/'SHA256SUMS').read_text()
        if previous is not None and manifest!=previous:raise RuntimeError('Independent artifact rebuild differs')
        previous=manifest
        final=output/('artifacts' if iteration==0 else 'rebuild-artifacts');shutil.copytree(artifacts,final)
        # Keep metadata and packages, not bulk generated compiler intermediates.
        shutil.rmtree(result/'target')
    (output/'reproducibility.json').write_text(json.dumps({'independent_builds':2 if args.reproduce else 1,'byte_identical':args.reproduce,**metadata},sort_keys=True,indent=2)+'\n')
    print('Candidate artifacts prepared; no release, tag or environment was published.')


if __name__=='__main__':main()
