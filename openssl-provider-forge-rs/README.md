# rust-openssl-core-provider

> [!CAUTION]
> This create is still a work-in-progress, and very experimental.

This crate contains FFI (Foreign Function Interface) bindings for
OpenSSL 3.2+, specifically for its Core and Provider API.

This is separate from [`rust-openssl`](https://github.com/sfackler/rust-openssl)
as this crate should only define constants and types necessary for
Rust [OpenSSL Providers][ossl:man:provider] to interact with
[OpenSSL Core][ossl:man:core], without a need to
actually link or depend on a specific OpenSSL binary.

Particularly this abstraction should cover:

- [`openssl-core`][ossl:man:core]
- [`openssl-provider-base`][ossl:man:provider-base]

(and their dependencies).

[ossl:man:provider]: https://www.openssl.org/docs/manmaster/man7/provider.html
[ossl:man:provider-base]: https://www.openssl.org/docs/manmaster/man7/provider-base.html
[ossl:man:core]: https://www.openssl.org/docs/manmaster/man7/openssl-core.h.html
