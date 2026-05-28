# vector-caver fork

Fork of [vectordotdev/vector](https://github.com/vectordotdev/vector) for the
[caver-collector](https://github.com/redeyesecurity/caver-collector) security-data
pipeline project. License: MPL 2.0 (modifications to upstream Vector source files
remain MPL; caver-proprietary sources/sinks live in separate crates).

## Branch model

| Branch | Purpose |
|--------|---------|
| `main` | caver customizations; base for all caver feature branches |
| `master` | upstream-sync branch; periodically fast-forward to vectordotdev/vector master; **no caver commits here** |

### Upstream sync workflow

```bash
# Fetch upstream changes into master (no caver commits here)
git fetch upstream master:master
git push origin master

# Merge upstream into main (resolves any conflicts with caver patches)
git checkout main
git merge master --no-ff -m "chore: merge upstream vector <version>"
git push origin main
```

Set up the upstream remote once:
```bash
git remote add upstream https://github.com/vectordotdev/vector.git
```

## caver extensions

caver-specific sources, sinks, and transforms live in dedicated crates
inside this repo rather than modifying upstream files where possible,
to minimize merge conflicts on upstream syncs.

See [caver-collector#61](https://github.com/redeyesecurity/caver-collector/issues/61)
for the project tracking issue.
