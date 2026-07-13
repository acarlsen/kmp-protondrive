package dev.carlsen.protondrive.sdk.nodes

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** Ports GetRevisionResponseDto - GET drive/v2/volumes/{volumeID}/files/{linkID}/revisions/{revisionID}?PageSize=N&FromBlockIndex=N. */
@Serializable
data class GetRevisionResponse(@SerialName("Code") val code: Int, @SerialName("Revision") val revision: RevisionDto)

/** Ports DetailedRevisionResponseDto. Only the fields needed for download are modeled. */
@Serializable
data class RevisionDto(
    /**
     * Armored detached signature over the concatenation of every thumbnail's and
     * every block's raw SHA-256 digest, in that order (thumbnails first, then
     * blocks in index order) - only present on the first page.
     */
    @SerialName("ManifestSignature") val manifestSignature: String? = null,
    @SerialName("SignatureEmail") val signatureEmail: String? = null,
    /** Only present on the first page - included in the manifest even though this SDK doesn't download thumbnail content itself. */
    @SerialName("Thumbnails") val thumbnails: List<ThumbnailDto> = emptyList(),
    @SerialName("Blocks") val blocks: List<BlockDto> = emptyList(),
)

/** Ports ThumbnailResponseDto. Only the hash is needed - it's part of the manifest signature's input even though thumbnail content itself isn't downloaded. */
@Serializable
data class ThumbnailDto(
    /** Base64-encoded SHA-256 digest. */
    @SerialName("Hash") val hash: String,
)

/** Ports BlockResponseDto. */
@Serializable
data class BlockDto(
    @SerialName("Index") val index: Int,
    /** Base64-encoded SHA-256 digest of this block's *encrypted* bytes. */
    @SerialName("Hash") val hash: String,
    @SerialName("Token") val token: String? = null,
    @SerialName("BareURL") val bareUrl: String? = null,
)
