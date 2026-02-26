# Mjolnir

Cross-platform antivirus with quantum-enhanced detection.

## Architecture

**11-crate Rust workspace** with a **Tauri v2 + React GUI**.

### Detection Engines (4, parallel via rayon)
- **Signature Engine** — YARA rules + BLAKE3 hash lookups
- **Heuristic Engine** — Import analysis, entropy, string patterns, packer detection
- **QAIO ML Engine** — Quantum Annealing-Inspired Optimization for feature selection + AdaBoost ensemble classifier
- **Static Analysis** — PE/ELF/Mach-O binary parsing via goblin

### Post-Quantum Cryptography
- **Hybrid Signatures** — Ed25519 + CRYSTALS-Dilithium3 (both must verify)
- **Key Exchange** — CRYSTALS-Kyber1024 KEM for secure update channel
- **Encryption** — AES-256-GCM for quarantine vault
- **Hashing** — BLAKE3

### Real-time Protection
- Cross-platform filesystem monitoring via `notify` crate
- Automatic scanning on file creation/modification

## Project Structure

```
crates/
  mjolnir-core/          # Shared types, traits, errors, config
  mjolnir-crypto/        # PQ crypto (Dilithium + Kyber + AES-GCM + BLAKE3)
  mjolnir-static/        # PE/ELF/Mach-O binary parsing
  mjolnir-signatures/    # YARA engine + signature database
  mjolnir-heuristics/    # Behavioral/heuristic analysis
  mjolnir-ml/            # Quantum annealing-inspired ML classifier
  mjolnir-scanner/       # Multi-threaded scan pipeline
  mjolnir-quarantine/    # Encrypted quarantine vault
  mjolnir-monitor/       # Real-time filesystem watcher
  mjolnir-updater/       # PQ-encrypted update client
  mjolnir-cli/           # Command-line interface
ui/                      # Tauri v2 + React/TypeScript GUI
rules/                   # YARA rule files
```

## Quick Start

### CLI
```bash
# Build
cargo build --release

# Scan a directory
./target/release/mjolnir scan ~/Downloads

# View quarantine
./target/release/mjolnir quarantine list

# Check status
./target/release/mjolnir status
```

### GUI
```bash
cd ui
npm install
npm run tauri dev
```

## YARA Rules

Custom rules go in `rules/custom/`. Rules use standard YARA syntax with severity tags:
- `critical` — Ransomware, rootkits
- `high` — Trojans, process injection
- `medium` — Cryptominers, keyloggers
- `low` — PUPs, test files
