# [kmp-protondrive](https://github.com/acarlsen/kmp-protondrive)
[![Kotlin version](https://img.shields.io/badge/Kotlin-2.4.0-blueviolet?logo=kotlin&logoColor=white)](http://kotlinlang.org)
![badge][badge-jvm]
![badge][badge-android]

Proton Drive client SDK implemented for Kotlin Multiplatform.
An unofficial port of the [proton-sdk](https://github.com/ProtonMail/proton-sdk) TypeScript client, using [PGPainless](https://pgpainless.org/) for OpenPGP — no native binaries or JNI.

> **This is a third-party, unofficial project — not affiliated with, endorsed by, or supported by Proton.**
> Per Proton's [SDK usage guidelines](https://github.com/ProtonMail/proton-sdk#usage-guidelines-for-personal-projects), this kind of integration is only sanctioned for **personal, non-commercial use**.

Features:
* Login with SRP (also with TOTP 2FA)
* Session persistence, refresh, and logout
* Browse folders
* Download file (with block-hash and manifest-signature verification)
* Upload file (new file or new revision, with optional thumbnails)
* Create folder
* Rename file/folder
* Move/copy file
* Trash file/folder

What's missing:
* Browser-based login (password login only)
* Moving/copying folders (`moveNode`/`copyNode` are files-only)
* Sharing, non-root volumes, photos, restoring from trash, permanent delete
* FIDO2/security-key 2FA

## Platform Support
- Android
- Desktop (JVM)

## To include in your project

Add the repository:
```kotlin
repositories {
    mavenCentral()
}
```

Put in your dependencies block:

```kotlin
implementation("dev.carlsen.protondrive:protondrive:1.0.0-beta01")
```

## How to use

```kotlin
// Initialize the SDK - appVersion identifies your app to Proton's API
val sdk = ProtonDriveSdk(
    appVersion = "external-drive-myapp@1.0.0",
    onSessionChanged = { session -> /* persist it - the SDK never touches disk */ },
)

// Log in to your Proton account
val loginResult = sdk.login("username", "password")
if (loginResult.twoFactorRequired) {
    sdk.submitTwoFactorCode("123456")
}
val account = sdk.finishLogin("password")!!

// ...or resume a previously persisted session instead
// val account = sdk.restoreSession(savedSession)

// Access your files
val drive = account.driveClient
val root = drive.getMyFilesRoot()
val children = drive.listChildren(root)

// Download a file
val file = children.first { it.name == "example.pdf" }
SystemFileSystem.sink(Path("download.pdf")).buffered().use { sink ->
    drive.downloadFile(file, parent = root, sink = sink) { downloadedBytes ->
        println("Downloaded $downloadedBytes bytes")
    }
}

// Upload a file
SystemFileSystem.source(Path("documents/report.pdf")).buffered().use { source ->
    drive.uploadFile(
        parent = root,
        name = "uploaded-report.pdf",
        source = source,
        mediaType = "application/pdf",
    )
}

// Create, rename, move, trash
val folder = drive.createFolder(root, "My New Folder")
drive.renameNode(file, parent = root, newName = "renamed.pdf")
drive.moveNode(file, oldParent = root, newParent = folder)
drive.trashNode(file)

// Logout when done
sdk.logout()
```

## CLI

The `cli` module is a runnable desktop CLI with an interactive file browser, useful for trying the SDK against a real account:

```bash
./gradlew :cli:installDist
./cli/build/install/cli/bin/cli
```

## Tests

```bash
./gradlew :sdk:jvmTest
```

All tests are self-contained (fake HTTP clients, a from-scratch SRP server) — none talk to the real Proton API.

[badge-android]: http://img.shields.io/badge/android-6EDB8D.svg?style=flat

[badge-jvm]: http://img.shields.io/badge/jvm-DB413D.svg?style=flat
