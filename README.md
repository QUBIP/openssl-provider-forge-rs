<div align="center">

  `openssl_provider_forge`

  <br />
  <a href="#about"><strong>Explore the docs »</strong></a>
  <br />
  <br />
  <a href="https://github.com/qubip/openssl-provider-forge-rs/issues/new?assignees=&labels=bug&template=01_BUG_REPORT.md&title=bug%3A+">Report a Bug</a>
  ·
  <a href="https://github.com/qubip/openssl-provider-forge-rs/issues/new?assignees=&labels=enhancement&template=02_FEATURE_REQUEST.md&title=feat%3A+">Request a Feature</a>
  ·
  <a href="https://github.com/qubip/openssl-provider-forge-rs/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+">Ask a Question</a>
</div>

<div align="center">
<br />

[![Project license](https://img.shields.io/github/license/qubip/openssl-provider-forge-rs.svg?style=flat-square)][LICENSE]

[![Pull Requests welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/qubip/openssl-provider-forge-rs/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![code with love by qubip](https://img.shields.io/badge/%3C%2F%3E%20with%20%E2%99%A5%20by-qubip%2Fnisec-ff1414.svg?style=flat-square)](https://github.com/orgs/QUBIP/teams/nisec)

</div>

> [!CAUTION]
>
> ### Development in Progress
>
> This project is **currently in development** and **not yet ready for production use**.
>
> **Expect changes** to occur from time to time, and at this stage, some features may be unavailable.

<details open="open">
<summary>Table of Contents</summary>

- [About](#about)
<!--
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
!-->
<!--
- [Usage](#usage)
!-->
- [Roadmap](#roadmap)
- [Support](#support)
- [Project assistance](#project-assistance)
- [Contributing](#contributing)
- [Authors & contributors](#authors--contributors)
- [Security](#security)
- [License](#license)
- [Acknowledgements](#acknowledgements)

</details>

---

## About

`openssl_provider_forge` is a Rust crate which
contains FFI (Foreign Function Interface) bindings
for `OpenSSL 3.2+`,
specifically for its `Core` and `Provider` API.

This is different from the [`rust-openssl`][crates:rust-openssl] crate,
which provides OpenSSL bindings for Rust applications.

In this crate, instead, we define constants and types
useful to author [OpenSSL Providers][ossl:man:provider]
written in Rust.
The goal of this crate is to facilitate
interactions with [OpenSSL Core][ossl:man:core],
without a need to actually link or depend on a specific
OpenSSL binary.

Particularly these abstractions cover:

- [`openssl-core`][ossl:man:core]
- [`openssl-provider-base`][ossl:man:provider-base]

(and their dependencies).

[ossl:man:provider]: https://docs.openssl.org/3.2/man7/provider/
[ossl:man:provider-base]: https://docs.openssl.org/3.2/man7/provider-base/
[ossl:man:core]: https://docs.openssl.org/3.2/man7/openssl-core.h/
[crates:rust-openssl]: https://crates.io/crates/openssl

> [!NOTE]
> **Note on naming conventions**
>
> The name of the repository follows `Github` conventions,
> while the name of the corresponding crate
> follows `crates.io` conventions,
> so the former is `openssl-provider-forge-rs`
> while the latter is `openssl_provider_forge`.

<!--
## Getting Started

### Prerequisites

> **[?]**
> What are the project requirements/dependencies?

### Installation

> **[?]**
> Describe how to install and get started with the project.
!-->

<!--
## Usage

> **[?]**
> How does one go about using it?
> Provide various use cases and code examples here.
!-->

## Roadmap

See the [open issues](https://github.com/qubip/openssl-provider-forge-rs/issues) for a list of proposed features (and known issues).

- [Top Feature Requests](https://github.com/qubip/openssl-provider-forge-rs/issues?q=label%3Aenhancement+is%3Aopen+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Top Bugs](https://github.com/qubip/openssl-provider-forge-rs/issues?q=is%3Aissue+is%3Aopen+label%3Abug+sort%3Areactions-%2B1-desc) (Add your votes using the 👍 reaction)
- [Newest Bugs](https://github.com/qubip/openssl-provider-forge-rs/issues?q=is%3Aopen+is%3Aissue+label%3Abug)

## Support

Reach out to the maintainers at one of the following places:

- [GitHub issues](https://github.com/qubip/openssl-provider-forge-rs/issues/new?assignees=&labels=question&template=04_SUPPORT_QUESTION.md&title=support%3A+)
- <security@romen.dev> to disclose security issues according to our [security documentation](docs/SECURITY.md).
- <coc@romen.dev> to report violations of our [Code of Conduct](docs/CODE_OF_CONDUCT.md).
- Details about the GPG keys to encrypt reports are included in our [security documentation](docs/SECURITY.md).

## Project assistance

If you want to say **thank you** or/and support active development:

- Add a [GitHub Star](https://github.com/qubip/openssl-provider-forge-rs) to the project.
- Mention this project on your social media of choice.
- Write interesting articles about the project, and cite us.

Together, we can make `openssl_provider_forge` **better**!

## Contributing

The GitHub repository primarily serves as a mirror,
and will be updated every time a new version is released.
It might not always be updated with the latest commits in between releases.
However, contributions are still very welcome!

Please read [our contribution guidelines](docs/CONTRIBUTING.md), and thank you for being involved!

## Authors & contributors

The original setup of this repository is by [NISEC](https://github.com/orgs/QUBIP/teams/nisec).

For a full list of all authors and contributors, see [the contributors page](https://github.com/qubip/openssl-provider-forge-rs/contributors).

## Security

In this project, we aim to follow good security practices, but 100% security cannot be assured.
This crate is provided **"as is"** without any **warranty**. Use at your own risk.

_For more information and to report security issues, please refer to our [security documentation](docs/SECURITY.md)._

## License

This project is licensed under the
[**Apache License, Version 2.0**](https://www.apache.org/licenses/LICENSE-2.0)
([Apache-2.0](https://spdx.org/licenses/Apache-2.0.html)).

```text
Copyright 2023-2025 Tampere University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

See [LICENSE][LICENSE] for more information.

[LICENSE]: LICENSE

## Acknowledgements

This work has been developed within the QUBIP project (<https://www.qubip.eu>),
funded by the European Union under the Horizon Europe framework programme
[grant agreement no. 101119746](https://doi.org/10.3030/101119746).
