# Changelog

All notable changes of the project. Newest first.

## v1.6.1 — versions without a date

- A `CHANGELOG.md` entry no longer needs a date: `## v1.4.1`, `## v1.4.1 — 2026-10-12` and `## v1.4.1 — a title` all work. GitHub dates the release itself.

## v1.6.0 — 2026-10-12 — versions and releases

- Settings → Version: the version of the site and the releases of the demo repository that came after it, with their notes. The API reads them from the Atom feed of the GitHub releases (`GET /api/version`) and keeps them an hour.
- Versions: every entry of this changelog starts with `vX.Y.Z`. After `main` is deployed, CI makes the tag and the GitHub release of the newest entry if it is not out yet. The site takes its version from the newest entry when it is deployed; `releases_repository` names the repository to compare with.

## v1.5.0 — 2026-10-12 — OpenPGP signatures and the Web Key Directory

- Everything SES sends is signed with OpenPGP (PGP/MIME `multipart/signed`): replies and new messages by the key of the alias, forwarded mail by the key of the relay address it comes from. Ed25519 keys with the address as the user id and no expiry, derived from the secret `/<name>/pgp-secret` (`pgp.tf`, `prevent_destroy`) and never stored; the alias keeps only the time its key was made. Parts a sender signed or encrypted are forwarded as they are.
- Web Key Directory on every domain: `/.well-known/openpgpkey/policy` and `/hu/<hash>` (by `?l=` or by the hash alone), through a CloudFront path and a public API Gateway route.
- The dialog of an alias shows its key: fingerprint, WKD link, "Download key (.asc)". API: `GET /api/aliases/<name>/key`.
- Settings → PGP switches the signatures off and on (`PUT /api/settings/pgp`); WKD stays. The variable `pgp_enabled` (`true`) removes PGP altogether, all but the secret.
- The `cryptography` package comes in the Lambda layer `<name>-cryptography`, built while planning by `lambda/build_layer.py` (provider `hashicorp/external`); `hashicorp/random` makes the secret. The deploy role needs the Lambda layers of the prefix, and the planner Python 3 with access to PyPI.
- Tests check the keys and signatures with GnuPG; without `cryptography` they are skipped.

## v1.4.0 — 2026-10-12 — correspondents and new messages

- Correspondents in the dialog of an alias: everyone with a reply address for it, who wrote or was added. Adding one makes their reply address at once; mail to it from the forwarding address goes to them from the alias, so a conversation can start from your mail client. API: `GET /api/aliases/<name>/relays`, `POST /api/relays`, `DELETE /api/relays/<reply address>`.
- A new plain text message from the page (`POST /api/messages`): from an alias to anyone; the recipient becomes a correspondent, the message goes to the log.
- Without mail (the demo) correspondents can still be added, nothing is sent: the buttons to write are hidden and the API answers `mail_disabled`. `max_relays` (200) caps the correspondents visitors add.
- "Two-step sign-in" is called two-factor authentication everywhere, as on the page.

## v1.3.0 — 2026-10-12 — no Terraform lock file

- `.terraform.lock.hcl` is no longer kept in the repository (it is in `.gitignore`): `terraform init` takes the newest AWS provider within the constraint in `terraform.tf`.

## v1.2.0 — 2026-10-11 — shared design

- The page: one design shared with the sibling projects (Hide My Email, the box inventory and the wiki): the same block of variables and components opens `web/styles.css` in all three and is kept identical — an indigo accent, system fonts, rounded cards, fields, buttons, dialogs, settings, tables and toasts. Light and dark themes follow the system setting. The sign-in card has the logo, the demo note above the fields, and the source link beside the language menu; the top bar shows the logo and switches Addresses and Messages with a segmented control.
- New favicon and BIMI logo in the shared style: a white envelope on indigo.
- Narrow screens: the address statistics wrap instead of running off the row, the search takes the full width.
- Deploy from a branch: a manual run of the workflow applies the branch it was started from, not only `main`, over the same demo site; the run summary names the branch and warns that the next push to `main` replaces it. Applies from different branches wait for each other.
- CI: the jobs moved to the shared reusable workflow of [Tozapid/demo-ci-cd-skeleton](https://github.com/Tozapid/demo-ci-cd-skeleton); `.github/workflows/terraform.yml` is a short caller, the same in all three projects. The Lambda tests run by discovery (`*_test.py`), the page tests run where `tests/web` exists, the state key is `<repository>/terraform.tfstate`.
- `main` is protected: changes go through pull requests, merged by squash once the checks `ci / Terraform format and validate`, `ci / Lambda tests` and `ci / Frontend tests` pass; merged branches are deleted.
- Settings in tabs (Password, Two-factor authentication, Language, API keys; the demo shows only the last two), opened by a Settings button in the top bar, with Sign out as its own button beside it, as in the box inventory and the wiki. The account menu is gone.

## v1.1.0 — 2026-10-11 — comparison

- README: a comparison table with icons against other alternatives (hosted alias services such as Apple Hide My Email, SimpleLogin and addy.io), what running it yourself gives (own domain, nobody in the middle, encryption, a small attack surface) and what the services do better. PGP encryption of forwarded mail is marked as planned.

## v1.0.0 — 2026-10-11 — first public version

- Disposable aliases on own domains with forwarding through SES, replies from the alias through relay addresses that show the sender (`office_at_shop_example_<code>@…`), and a message log with attachments served by CloudFront behind a signed cookie.
- Web page on S3 and CloudFront, one distribution per domain (module `site/`), Cognito sign-in with optional TOTP, interface in English, Russian, French and Italian.
- addy.io-compatible API for the Bitwarden username generator and the addy.io browser extension, with personal API keys stored as hashes.
- Test environment by default: no mail and no domain, the page on its CloudFront address, a published demo sign-in, an hourly reset to the examples of `seed/seed.json`, caps on aliases and keys. Production by listing domains (`examples/production.tfvars`).
- GitHub Actions deploy with OIDC: no AWS keys, a role trusted only by the `demo` environment.
