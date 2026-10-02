# Rete

Reusable Rust networking and authentication libraries, built with Rust 2024.

| Crate | Responsibility |
| --- | --- |
| [`arche-web`](arche-web/README.md) | Axum serving, bounded HTTP forwarding, and JSON errors |
| [`firestore-common`](firestore-common/README.md) | Validated Firestore connections and strict typed document access |
| [`phylax-core`](phylax-core/README.md) | OAuth, JWT, PKCE, and refresh-token primitives and endpoint contracts |
| [`phylax-gcp`](phylax-gcp/README.md) | Firestore authentication stores and configurable identity directories |
| [`phylax-oidc`](phylax-oidc/README.md) | Provider-neutral OIDC authentication |

Rete is an independent Cargo workspace. It has no dependency on application
repositories or a private Cargo registry. Local sibling dependencies carry version
requirements so Cargo can resolve them from crates.io when packaged.

## Development

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo package --workspace --locked --registry crates-io
```

The package command creates and verifies local archives; it does not upload them.
Publication is restricted to crates.io by the manifests and remains an explicit
operator action. The package manifests do not trigger publication automatically.

When checked out as `komputation/rete`, sibling applications use versioned path
dependencies. Initialize the submodule before building those applications.

Licensed under AGPL-3.0-only; see [LICENSE](LICENSE).
