#!/usr/bin/env python3
"""Run unchanged pinned Swift light-client verifier on Rust-generated witnesses."""
import copy, hashlib, json, os, pathlib, subprocess, tempfile
repo=pathlib.Path(__file__).resolve().parents[1]
reference=repo.parent/'lattice-node'; lattice=repo.parent/'Lattice'; cache=pathlib.Path('/tmp/lattice-genesis-oracle')
node_rev='3df9e0a786c7b103a3da88d1c3881efc81706255'; lattice_rev='dda2d852429a27be6043599b63bde81530cd9514'
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=reference,text=True).strip()==node_rev
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=lattice,text=True).strip()==lattice_rev
for original in (lattice/'Sources').rglob('*.swift'): assert original.read_bytes()==(cache/original.relative_to(lattice)).read_bytes()
lock_hash=hashlib.sha256((cache/'Package.resolved').read_bytes()).hexdigest()
assert lock_hash=='958f69bd3ec734a372e8cd94e3d09d593674a1025979a2abe2b45a6f08cfc9a6'
source=reference/'Sources/LatticeLightClient/LightClientProtocol.swift'
target=cache/'Sources/LightClientOracle'; target.mkdir(exist_ok=True)
(target/'LightClientProtocol.swift').write_bytes(source.read_bytes())
(target/'Oracle.swift').write_bytes((repo/'tools/oracle.swift').read_bytes())
p=cache/'Package.swift'; text=p.read_text()
if 'name: "LightClientOracle"' not in text:
    p.write_text(text.replace('    targets: [\n','    targets: [\n        .executableTarget(name: "LightClientOracle", dependencies: ["Lattice", .product(name: "cashew", package: "cashew")]),\n',1))
with tempfile.TemporaryDirectory() as tmp:
    fixtures=pathlib.Path(tmp)/'input.json'
    subprocess.run(['cargo','test','-q','export_swift_oracle_inputs_when_requested'],cwd=repo,env={**os.environ,'LIGHT_CLIENT_FIXTURE_OUTPUT':str(fixtures)},check=True)
    seeds=json.loads(fixtures.read_text()); rows=[]
    def add(name,kind,proof,expected): rows.append(dict(name=name,kind=kind,proof=proof,expected=expected))
    for kind,seed in seeds.items():
        wire='account' if kind.startswith('account') else 'dictionary'
        add(kind,wire,seed,True)
        for field in ['blockHeight','stateRoot']:
            p=copy.deepcopy(seed);p[field]=p[field]+1 if isinstance(p[field],int) else 'invalid';add(kind+'-'+field,wire,p,False)
        p=copy.deepcopy(seed);p['witness']=[];add(kind+'-missing-witness',wire,p,False)
        p=copy.deepcopy(seed);p['witness'][0]['data']='%%%';add(kind+'-bad-base64',wire,p,False)
        if wire=='account':
            p=copy.deepcopy(seed);p['balance']+=1;add(kind+'-wrong-balance',wire,p,False)
            p=copy.deepcopy(seed);p['nonce']+=1;add(kind+'-wrong-nonce',wire,p,False)
            p=copy.deepcopy(seed);p['header']['timestamp']+=1;add(kind+'-wrong-header',wire,p,False)
        else:
            p=copy.deepcopy(seed);p['claims']=[];add(kind+'-empty-claims',wire,p,True)
            p=copy.deepcopy(seed);p['claims'][0]['value']='wrong';add(kind+'-wrong-claim',wire,p,False)
            p=copy.deepcopy(seed);p['witness'].append(p['witness'][0]);add(kind+'-duplicate-witness',wire,p,False)
            p=copy.deepcopy(seed);p['claims']=[{'key':'absent','value':None}];add(kind+'-absence',wire,p,True)
    fixtures.write_text(json.dumps(rows))
    verdicts=json.loads(subprocess.check_output(['swift','run','--package-path',str(cache),'--force-resolved-versions','LightClientOracle',str(fixtures)]))
    for row in rows: row['swift']=verdicts[row['name']]
    mismatches=[r['name'] for r in rows if r['swift']!=r['expected']]
    assert not mismatches,mismatches
    data=json.dumps(rows,sort_keys=True,indent=2)+'\n'
    (repo/'tests/swift-proofs.json').write_text(data)
    (repo/'tests/swift-evidence.json').write_text(json.dumps(dict(node_revision=node_rev,lattice_revision=lattice_rev,source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),package_resolved_sha256=lock_hash,corpus_sha256=hashlib.sha256(data.encode()).hexdigest(),cases=len(rows),method='Unmodified full LightClientProtocol.swift compiled with pinned actual Lattice and cashew libraries; Rust-generated witnesses and adversarial mutations.'),indent=2)+'\n')
    print(f'{len(rows)} Swift proof verdicts passed')
