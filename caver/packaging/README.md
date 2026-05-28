# caver packaging

Tracked: caver-collector#73

Planned targets:
- Docker multi-arch distroless image (amd64 + arm64)
- Homebrew formula
- .deb and .rpm via nfpm
- Signed MSI (Windows)

Artifacts are built from the `caver/` workspace via `cargo build --release`.
