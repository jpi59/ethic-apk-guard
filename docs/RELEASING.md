# Release handover

Release signing is local and opt-in. Do not commit private keys, passwords, or
signing configuration.

1. Supply `KEYSTORE_PATH`, `KEY_ALIAS`, `STORE_PASSWORD`, and `KEY_PASSWORD` to
   Gradle from the maintainer's protected environment.
2. Run `./gradlew :app:clean :app:assembleRelease`.
3. Verify the APK with `apksigner verify --verbose --print-certs` and publish a
   SHA-256 checksum alongside any release artifact.

F-Droid builds from the public source and signs its own artifact. A local
   release signature must not be presented as F-Droid's signature.
