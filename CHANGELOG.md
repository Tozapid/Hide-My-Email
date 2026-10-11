# Changelog

All notable changes of the project. Newest first.

## 2026-10-11 — shared design

- The page: one design shared with the sibling projects (Hide My Email, the box inventory and the wiki): the same block of variables and components opens `web/styles.css` in all three and is kept identical — an indigo accent, system fonts, rounded cards, fields, buttons, dialogs, settings, tables and toasts. Light and dark themes follow the system setting. The sign-in card has the logo, the demo note above the fields, and the source link beside the language menu; the top bar shows the logo and switches Addresses and Messages with a segmented control.
- New favicon and BIMI logo in the shared style: a white envelope on indigo.
- Narrow screens: the address statistics wrap instead of running off the row, the search takes the full width.
- Deploy from a branch: a manual run of the workflow applies the branch it was started from, not only `main`, over the same demo site; the run summary names the branch and warns that the next push to `main` replaces it. Applies from different branches wait for each other.

## 2026-10-11 — comparison

- README: a comparison table with icons against other alternatives (hosted alias services such as Apple Hide My Email, SimpleLogin and addy.io), what running it yourself gives (own domain, nobody in the middle, encryption, a small attack surface) and what the services do better. PGP encryption of forwarded mail is marked as planned.

## 2026-10-11 — first public version

- Disposable aliases on own domains with forwarding through SES, replies from the alias through relay addresses that show the sender (`office_at_shop_example_<code>@…`), and a message log with attachments served by CloudFront behind a signed cookie.
- Web page on S3 and CloudFront, one distribution per domain (module `site/`), Cognito sign-in with optional TOTP, interface in English, Russian, French and Italian.
- addy.io-compatible API for the Bitwarden username generator and the addy.io browser extension, with personal API keys stored as hashes.
- Test environment by default: no mail and no domain, the page on its CloudFront address, a published demo sign-in, an hourly reset to the examples of `seed/seed.json`, caps on aliases and keys. Production by listing domains (`examples/production.tfvars`).
- GitHub Actions deploy with OIDC: no AWS keys, a role trusted only by the `demo` environment.
