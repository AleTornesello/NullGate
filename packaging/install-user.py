#!/usr/bin/env python3
"""Install an unpacked candidate for the current user; preserve existing configuration/state."""
import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, default=Path.home()/'.local')
    parser.add_argument('--config-dir', type=Path, default=Path.home()/'.config/nullgate')
    parser.add_argument('--data-dir', type=Path, default=Path.home()/'.local/share/nullgate')
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error('Run the user installer as a normal user; use the Debian package for system installation')
    bundle = Path(__file__).resolve().parent
    prefix, config, data = [p.expanduser().absolute() for p in (args.prefix, args.config_dir, args.data_dir)]
    for p in [config, data]:
        if p.is_symlink():
            parser.error('Configuration/data directories must not be symlinks')
        p.mkdir(parents=True, exist_ok=True, mode=0o700)
        if p.stat().st_uid != os.geteuid() or p.stat().st_mode & 0o077:
            parser.error('Configuration/data directories must be owned by the current user with mode 0700')
    destination = prefix/'bin'
    destination.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.nullgate-', dir=destination)
    os.close(fd)
    try:
        shutil.copyfile(bundle/'bin/nullgate', temporary)
        os.chmod(temporary, 0o755)
        os.replace(temporary, destination/'nullgate')
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    text = (bundle/'config/nullgate.example.toml').read_text()
    text = '\n'.join('data_dir = '+json.dumps(str(data)) if line.startswith('data_dir =') else line for line in text.splitlines())+'\n'
    try:
        fd=os.open(config/'nullgate.toml', os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd,'w') as output: output.write(text)
    print('Installed binary; existing configuration and data preserved. Provision the first Administrator before starting.')

if __name__ == '__main__': main()
