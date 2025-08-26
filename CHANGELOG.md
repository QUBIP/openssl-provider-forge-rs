# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.4] - 2025-08-27

### Changed

- Bump to 0.8.4
- Update Changelog for v0.8.3
- Lower log level for selection debug
- Move upcalls module from aurora to forge
- Rename decoder module to transcoders and add Encoder trait

## [0.8.3] - 2025-04-23

### Added

- Add signature utilities
- Add decoder module for OpenSSL support
- Add Clone and Copy to Selection struct
- Add test configuration flag
- Add handleResult macro for error handling
- Add documentation for keymgmt module
- Add constants for DTLS sigalg capabilities
- Add ffi_c_types module for FFI re-exports
- Add pull_request_target event handling

### Changed

- Bump to 0.8.3
- Cargo update
- Improve macro type safety
- Deprecate re-export of `operations::keymgmt`
- Modularize keymgmt operations
- Simplify error mapping in setup

### Fixed

- Fix spelling
- Implement `new_const_octetstring` logic

## [0.8.1] - 2025-03-16

### Added

- Add examples and optional param handling
- Add TLS Signature Algorithm support
- Add TLS and DTLS version enums
- Add TLS group support
- Add missing docs for CONST_OSSL_PARAM and OSSLParam types
- Add setup function to all test cases

### Changed

- Bump to 0.8.1
- Enhance documentation for SIGALG_NAME
- Format TOML files
- Update documentation and examples
- Refine TLS and DTLS version handling
- Update local Cargo.lock dependencies
- Update TODOs
- Migrate to modern Rust module file naming convention
- Update dependencies and add test setup

### Fixed

- Fix punctuation in documentation
- Handle null pointers in data getters
- Use log::trace instead of log::debug

## [0.8.0] - 2025-03-08

### Added

- Add CODEOWNERS file
- Add test-doc job
- Add workflow similar to the gitlab one
- Add .gitignore to exclude /target directory
- Add initial GitLab CI configuration
- Add unit tests for OSSLParam::variant_name()
- Add missing newlines in osslparams module

### Changed

- Bump to 0.8.0
- Update labels workflow
- Add Changelog
- Limit CodeQL tasks to github-action workflows
- Update CODEOWNERS
- Disable lock worflow
- Update label workflows
- Revise github labels
- Revise LICENSE to fully conform to Apache-2.0
- Improve compatibility with rustdoc inclusion
- Include readme at crate level
- Move OSSL_PARAM_UNMODIFIED constant
- Re-export FFI bindings for better usability
- Edit pass on stale documentation
- Remove stale allow(dead_code) annotation
- Add examples for OSSLParamIterator and IntoIterator
- Make traits public again
- `new_const_*()` associated functions now take an Option as value
- Add missing docs
- Remove ossl_param_locate_raw

### Fixed

- Fix most failing doctests (Examples)

### Removed

- Remove OSSLParam::inner_data()

## [0.7.1] - 2025-02-21

### Added

- Add GPG keys for secure communication

### Changed

- Bump version to 0.7.1
- Update note on naming conventions

### Fixed

- Correct typo in README.md

### Removed

- Remove forbidden module

## [0.7.0] - 2025-02-18

### Added

- Add new OSSLParam methods
- Add iterator support for OSSLParam
- Add pkg-config dependency and update build.rs
- Add debug and selection support for key management
- Add OSSLParam::try_new_vec() to convert a C param array pointer to a Vec<OSSLParam>
- Add octet string param type
- Add gen_set_params and gen_settable_params for libcrux X25519MLKEM768 adapter
- Add UTF8 string param type in combined module with UTF8 pointer param type
- Added Unit Tests
- Add OSSLParam implementation in modules
- Add OSSL_PARAM implementation using marker traits

### Changed

- Update Cargo.toml version to 0.7.0
- Move to top directory after splitting `openssl-provider-forge-rs` from monorepo
- Alias CONST_OSSL_PARAM in bindings module
- Rename `osslcb` as `ossl_callback`
- Introduce OSSLCallback for cleaner handling
- Feat(osslparams): introduce CONST_OSSL_PARAM
- Implement custom Debug for IntData and UIntData
- Implement custom Debug for Utf8StringData
- Implement new constructors
- Improve clarity for `get_inner` for OSSLParam::Utf8Ptr
- Implement `get_inner` for OSSLParam::Utf8String
- Rename rust-openssl-core-provider to openssl_provider_forge
- Implement an Iterator that gives OSSLParam structs from a OSSL_PARAM pointer
- Clean up a few more old uses of ossl_param_st
- Use &mut instead of \*mut to store the OSSL_PARAM reference
- Use OSSL_PARAM instead of ossl_param_st everywhere
- Use $crate in dispatch_table_entry macro
- Apply `cargo fmt`
- Replace OSSLParam::try_new_vec() with an impl From<&mut ossl_param_st> for Vec<OSSLParam>
- Iterate directly over C params array with `ossl_param_locate_raw`
- Update setter for octet string param to more closely match OSSL C implementation
- Update setter for UTF-8 string param to more closely match OSSL C implementation
- Use $crate in impl_setter macro definition
- Use u32 for UInt params in TLS group params
- Allocate memory and set data_size when creating new empty params
- Create mutable reference instead of copying param in Int and UInt types
- Disable function type check
- [aurora/src/adapters/libcrux] Refactor structure
- Bug Fix: Dereference & create mutable reference
- Rearrange tests
- Minimize how much code is in unsafe blocks in `TypedOSSLParamData` impls
- Ensure function has expected type when creating dispatch table entry
- Refactor project structure
- Restructure osslparams module
- [aurora/src] Remove requirement on nightly experimental features
- Start importing OSSL_PARAM work
- Initial commit
- Initial commit with README and LICENSE

### Fixed

- Fmt::Debug must be infallible
- Use `$crate` in macro to ensure proper resolution of `OSSL_DISPATCH`

### Removed

- Remove all naked `unwrap()`

[0.8.4]: https://github.com///compare/v0.8.3..v0.8.4
[0.8.3]: https://github.com///compare/v0.8.1..v0.8.3
[0.8.1]: https://github.com///compare/v0.8.0..v0.8.1
[0.8.0]: https://github.com///compare/v0.7.1..v0.8.0
[0.7.1]: https://github.com///compare/v0.7.0..v0.7.1

<!-- generated by git-cliff -->
