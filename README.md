Bulwark is a simple file encryption tool available in both CLI and GUI versions. It uses XChaCha20Poly1305 or AES-GCM for encryption. It includes optional compression using Zstandard.

## Installation

Ensure you have [Rust](https://rustup.rs/) installed, then clone the repository and build the project:

```bash
git clone https://github.com/DAHNEEV/bulwark.git
cd bulwark

cargo build --release
```

## Usage

- GUI, simply launch the executable without arguments:
```bash
./bulwark
```

- CLI, use help command and read!
```bash
./bulwark encrypt --help
./bulwark decrypt --help
```
