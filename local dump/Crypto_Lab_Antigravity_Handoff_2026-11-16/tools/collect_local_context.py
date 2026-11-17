#!/usr/bin/env python3
"""Read-only source inventory. Writes only to a NEW folder outside all worktrees.
No network, installation, tests, publication, credentials or process management.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from datetime import datetime, timezone

MAX_BYTES = 5 * 1024 * 1024
SOURCES = ['README.md','AGENTS.md','CLAUDE.md','GEMINI.md','pyproject.toml',
 'scripts/verify.ps1','scripts/invoke-uv.ps1','docs/superpowers/plans',
 'docs/superpowers/specs','docs/decisions','docs/development',
 'offline_data/README.md','offline_data/pyproject.toml',
 'offline_data/scripts/verify-offline.ps1']

def inside(p: Path, root: Path) -> bool:
    return p == root or root in p.parents

def git(root: Path, *args: str) -> str:
    try:
        r = subprocess.run(['git','--no-optional-locks','-c','core.fsmonitor=false',
                            '-C',str(root),*args], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError('Read-only Git command did not complete: '+args[0]) from e
    if r.returncode:
        raise RuntimeError(f'Read-only Git command failed: {args[0]}, exit {r.returncode}')
    return r.stdout.decode('utf-8', errors='replace')

def save(p: Path, data: object) -> None:
    p.write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

def collect(repository: Path, output: Path) -> dict:
    root = repository.expanduser().resolve(strict=True)
    if root != Path(git(root,'rev-parse','--show-toplevel').strip()).resolve():
        raise ValueError('--repo must name the actual worktree root')
    out = output.expanduser().resolve()
    wt = git(root,'worktree','list','--porcelain')
    roots = [Path(l[9:]).resolve() for l in wt.splitlines() if l.startswith('worktree ')]
    if inside(out, root) or any(inside(out,p) for p in roots):
        raise ValueError('--out must be outside all registered product worktrees')
    if out.exists():
        raise ValueError('--out must be new; existing evidence is not overwritten')
    head = git(root,'rev-parse','HEAD').strip()
    status = git(root,'status','--porcelain=v1','--untracked-files=normal')
    branch = git(root,'branch','--show-current').strip()
    refs = git(root,'for-each-ref','--format=%(refname) %(objectname)','refs/heads')
    log = git(root,'log','-40','--format=%H%x09%cI%x09%s')
    paths = git(root,'ls-files','-z','--',*SOURCES).split('\0')
    out.mkdir(parents=True,exist_ok=False)
    inventory, headings, unavailable = [], [], []
    for rel in sorted(set(paths)):
        if not rel: continue
        p=root/rel
        try:
            target=p.resolve(strict=True)
            if p.is_symlink() or not inside(target,root) or not target.is_file():
                unavailable.append({'path':rel,'reason':'not a plain in-root file'}); continue
            if target.suffix.lower() not in {'.md','.txt','.toml','.ps1'}: continue
            if target.stat().st_size>MAX_BYTES:
                unavailable.append({'path':rel,'reason':'above size bound'}); continue
            data=target.read_bytes()
            if len(data)>MAX_BYTES:
                unavailable.append({'path':rel,'reason':'grew above size bound'}); continue
            dest=out/'repository_documents'/rel
            dest.parent.mkdir(parents=True,exist_ok=True); dest.write_bytes(data)
            inventory.append({'path':rel,'bytes':len(data),
              'sha256':hashlib.sha256(data).hexdigest(),
              'source':'working-tree bytes, not assumed HEAD-identical'})
            for no,line in enumerate(data.decode('utf-8-sig',errors='replace').splitlines(),1):
                if re.match(r'^#{1,6}\s+',line) and re.search(
                        r'\b(task|stage|prerequisite|blocker|acceptance|decision)\b',line,re.I):
                    headings.append({'path':rel,'line':no,'heading':line,
                                     'status':'SOURCE_HEADING_NOT_ACCEPTANCE'})
        except OSError:
            unavailable.append({'path':rel,'reason':'unreadable; no absence assumed'})
    head_after=git(root,'rev-parse','HEAD').strip()
    status_after=git(root,'status','--porcelain=v1','--untracked-files=normal')
    result={'captured_at_utc':datetime.now(timezone.utc).isoformat(),
       'repository_root':str(root),'branch':branch,'head_before':head,'head_after':head_after,
       'status_before':status,'status_after':status_after,
       'head_and_status_stable':head==head_after and status==status_after,
       'atomic_snapshot':False,'local_refs':refs.splitlines(),'worktrees':wt.splitlines(),
       'recent_commits':log.splitlines(),'files':inventory,'unavailable':unavailable,
       'network_used':False,'product_verification':False,'contains_private_local_paths':True}
    save(out/'LOCAL_INVENTORY.json',result);save(out/'EXACT_PLAN_HEADINGS.json',headings)
    (out/'READ_ME.txt').write_text('Read-only inventory, not acceptance. Working-tree copies are not an atomic snapshot.\nKeep local paths private. No journals, credentials or environment values collected.\n',encoding='utf-8')
    return result

def main() -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo',type=Path,required=True);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    try: r=collect(a.repo,a.out)
    except (OSError,ValueError,RuntimeError) as e:
        print('COLLECTION_REFUSED: '+str(e),file=sys.stderr); return 2
    print('COLLECTED_DOCUMENTS='+str(len(r['files'])))
    print('HEAD_AND_STATUS_STABLE='+str(r['head_and_status_stable']))
    print('NO_PRODUCT_VERIFICATION_OR_ACCEPTANCE_CLAIMED')
    return 0 if r['head_and_status_stable'] else 3

if __name__=='__main__':
    raise SystemExit(main())
