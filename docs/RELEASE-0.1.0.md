# Ethic APK Guard 0.1.0

Initial public technical release under GPLv3-or-later.

This release provides local APK compatibility analysis, explicit handoff to
Android's installer, optional public F-Droid context, and conservative
recognition of APKS/XAPK containers. It is not a malware certification and it
does not yet install split-package bundles.

The distributed APK was signed locally with the maintainer's dedicated
Android RSA-4096 key. Public certificate SHA-256 fingerprint:

`06b21d5a6b7a8d71bca523fecf7e50cf0c7655fd1d903ba5829f2841d762fa74`

APK SHA-256:

`d98ef840d8de93e4a2b47b3fa610640980ef3743d0b4f39f907e8c909dd81e57`

F-Droid builds from source and uses its own signing key; this local release
signature must not be confused with F-Droid's signature.
