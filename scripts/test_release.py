import gzip
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

from package_release import archive
from verify_test_run import summarize


class ReleaseTests(unittest.TestCase):
    def test_release_harness_requires_nonzero_complete_coverage(self):
        prefix='Running tests/end_to_end.rs\n'
        self.assertFalse(summarize(prefix+'test result: ok. 0 passed; 0 failed; 0 ignored;')['guard_ok'])
        self.assertFalse(summarize(prefix+'test result: ok. 2 passed; 0 failed; 1 ignored;')['guard_ok'])
        self.assertTrue(summarize(prefix+'test result: ok. 3 passed; 0 failed; 0 ignored;')['guard_ok'])
    def test_archive_ignores_host_mtime_and_owners(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);tree=root/'candidate';tree.mkdir();(tree/'bin').mkdir()
            binary=tree/'bin/nullgate';binary.write_bytes(b'fixed bytes');binary.chmod(0o755)
            archive(tree,root/'one.tar.gz',1234567890)
            os.utime(binary,(1800000000,1800000000))
            archive(tree,root/'two.tar.gz',1234567890)
            self.assertEqual((root/'one.tar.gz').read_bytes(),(root/'two.tar.gz').read_bytes())
            with tarfile.open(root/'one.tar.gz') as tar:
                info=tar.getmembers()[0];self.assertEqual((info.uid,info.gid,info.mtime,info.mode),(0,0,1234567890,0o755))
    def test_user_install_preserves_config_and_state_and_replaces_binary(self):
        if os.geteuid()==0:self.skipTest('Normal-user installer requires a non-root test user')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);bundle=root/'bundle';(bundle/'bin').mkdir(parents=True);(bundle/'config').mkdir()
            (bundle/'bin/nullgate').write_bytes(b'version one')
            (bundle/'config/nullgate.example.toml').write_text('schema_version = 1\ndata_dir = "../data"\n')
            installer=Path(__file__).resolve().parents[1]/'packaging/install-user.py'
            import shutil;shutil.copyfile(installer,bundle/'install-user.py')
            command=['python3',str(bundle/'install-user.py'),'--prefix',str(root/'prefix'),'--config-dir',str(root/'config'),'--data-dir',str(root/'data')]
            subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
            config=root/'config/nullgate.toml';config.write_text('operator configuration')
            (root/'data/state').write_bytes(b'preserve')
            (bundle/'bin/nullgate').write_bytes(b'version two')
            subprocess.run(command,check=True,stdout=subprocess.DEVNULL)
            self.assertEqual(config.read_text(),'operator configuration');self.assertEqual((root/'data/state').read_bytes(),b'preserve')
            self.assertEqual((root/'prefix/bin/nullgate').read_bytes(),b'version two')
            self.assertEqual((root/'data').stat().st_mode & 0o777,0o700)
    def test_failed_compiler_stops_inner_builder(self):
        shell=(Path(__file__).resolve().parents[1]/'packaging/build-in-container.sh').read_text().split("--clear-groups sh -c '\n",1)[1].rsplit("'",1)[0]
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);cargo=root/'cargo';cargo.write_text('#!/bin/sh\nexit 17\n');cargo.chmod(0o755)
            shell=shell.replace('cd /src','cd '+str(root))
            result=subprocess.run(['sh','-c',shell],env={**os.environ,'PATH':str(root)+os.pathsep+os.environ['PATH']},capture_output=True,timeout=5)
            self.assertEqual(result.returncode,17)

if __name__=='__main__':unittest.main()
