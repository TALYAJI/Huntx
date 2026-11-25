# Changelog

## 1.1.0

### Security
- Fixed script injection in the HTML report from strings inside an analysed app.
- ADB commands are quoted for both the local and the device shell.
- CSV formula injection, oversized ZIP members and XML entities are blocked.
- Traffic redaction now covers URLs and bodies, not only headers.
- Postman exports no longer aim relative routes at an unrelated host.

### Fixed
- Signer fingerprints were hashes of the signature file; they are now real X.509 fingerprints.
- Dangerous permissions, networking libraries, secrets and cleartext state were always empty or zero.
- Component names were missing from CSV and the attack surface tree.
- Class paths such as `android/support/v4/...` were reported as API endpoints.
- Endpoints were attributed to any class mentioning the same host.
- Filenames containing dots crashed `scan`; rescans mixed in old copies and stale APKs.
- Resuming a session from the menu opened an empty fake session.
- A second traffic import erased the first; invalid input produced a made-up report.
- Passport and mapping endpoint ids could disagree.

- Bounty drafts now cover cleartext, user CAs, backup and debug signing, and no longer call a cloud URL a credential.
- Email hosts, Java packages and `R.string.*` references are no longer reported as domains.

### Added
- Retrofit annotation extraction from DEX, `resources.arsc` parsing, v2/v3 signing blocks.
- `apks`, `search`, `report`, `notes --add`, `--version`, OpenAPI export, menu operation 21.
- CI for Linux, macOS and Windows.

### Changed
- License is MIT. Python 3.10 or newer is required.
- `androguard`, `jinja2` and `networkx` were unused and are no longer required.
- `python huntx.py` is replaced by `huntx` or `python -m huntx`; the script shadowed the package and broke builds.
- Removed the unreachable `huntx.dashboard` and `huntx.storage.models` modules.
