# Change Log

## 1.0.0-beta03 *(2026-07-26)*

- Fix `createFolder` surfacing a confusing crypto-verification error instead of
  `NodeWithSameNameExistsValidationError` when the name collides with an orphaned,
  undecryptable sibling link
- `listChildren` now exposes the unencrypted name-hash on undecryptable sibling placeholders

## 1.0.0-beta02 *(2026-07-13)*

- Fix issue with parsing session key

## 1.0.0-beta01 *(2026-07-10)*

- Initial release
