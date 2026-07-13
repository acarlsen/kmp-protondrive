package dev.carlsen.protondrive.sdk.nodes

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Ports PrimaryRootShareResponseDto - GET drive/v2/shares/my-files. Note this
 * is genuinely nested (Volume/Share/Link as separate objects) - an earlier
 * version of this file wrongly modeled it as the flat BootstrapShareResponseDto,
 * which is actually the shape of the *different* GET drive/shares/{shareID}
 * endpoint. Confirmed against a real account's response.
 */
@Serializable
data class PrimaryRootShareResponse(
    @SerialName("Code") val code: Int,
    @SerialName("Volume") val volume: VolumeDto,
    @SerialName("Share") val share: ShareDto,
    /** The root folder's own link details - already fully loaded here, no follow-up drive/v2/volumes/{id}/links call needed for the root. */
    @SerialName("Link") val link: LinkDetails,
)

@Serializable
data class VolumeDto(@SerialName("VolumeID") val volumeId: String)

@Serializable
data class ShareDto(
    @SerialName("ShareID") val shareId: String,
    @SerialName("CreatorEmail") val creatorEmail: String,
    @SerialName("Key") val key: String,
    @SerialName("Passphrase") val passphrase: String,
    @SerialName("PassphraseSignature") val passphraseSignature: String,
    @SerialName("AddressID") val addressId: String,
)

/** Ports ListChildrenResponseDto - GET drive/v2/volumes/{volumeID}/folders/{linkID}/children. */
@Serializable
data class ListChildrenResponse(
    @SerialName("Code") val code: Int,
    @SerialName("LinkIDs") val linkIds: List<String> = emptyList(),
    @SerialName("AnchorID") val anchorId: String? = null,
    @SerialName("More") val more: Boolean = false,
)

/** Ports the request body for POST drive/v2/volumes/{volumeID}/links. */
@Serializable
data class LoadLinksRequest(@SerialName("LinkIDs") val linkIds: List<String>)

/** Ports LoadLinkDetailsResponseDto. */
@Serializable
data class LoadLinksResponse(@SerialName("Code") val code: Int, @SerialName("Links") val links: List<LinkDetails> = emptyList())

/** Ports FolderDetailsDto/FileDetailsDto, merged - Folder/File are mutually exclusive per LinkDto.Type. */
@Serializable
data class LinkDetails(
    @SerialName("Link") val link: LinkDto,
    @SerialName("Folder") val folder: FolderDto? = null,
    @SerialName("File") val file: FileDto? = null,
)

/** Ports LinkDto. */
@Serializable
data class LinkDto(
    @SerialName("LinkID") val linkId: String,
    @SerialName("Type") val type: Int,
    @SerialName("ParentLinkID") val parentLinkId: String? = null,
    @SerialName("ModifyTime") val modifyTime: Long = 0,
    @SerialName("Name") val name: String,
    /** Current lookup hash of this node's name - needed as `OriginalHash` when renaming (optimistic concurrency). */
    @SerialName("NameHash") val nameHash: String? = null,
    @SerialName("NodeKey") val nodeKey: String,
    @SerialName("NodePassphrase") val nodePassphrase: String,
    @SerialName("NodePassphraseSignature") val nodePassphraseSignature: String,
    @SerialName("SignatureEmail") val signatureEmail: String? = null,
    @SerialName("NameSignatureEmail") val nameSignatureEmail: String? = null,
)

@Serializable
data class FolderDto(
    @SerialName("NodeHashKey") val nodeHashKey: String? = null,
    @SerialName("XAttr") val xAttr: String? = null,
)

@Serializable
data class FileDto(
    @SerialName("ActiveRevision") val activeRevision: ActiveRevisionDto? = null,
    /** Base64-encoded, binary PKESK-only packet - the file content's session key, encrypted to this node's own key. Needed to download/decrypt file content. */
    @SerialName("ContentKeyPacket") val contentKeyPacket: String? = null,
    /** Armored detached signature over the *plain* session key bytes (not the encrypted packet), signed with the node key. Legacy accounts may sign differently - verified best-effort. */
    @SerialName("ContentKeyPacketSignature") val contentKeyPacketSignature: String? = null,
)

@Serializable
data class ActiveRevisionDto(
    /** Needed to fetch this file's blocks via GET drive/v2/volumes/{volumeID}/files/{linkID}/revisions/{revisionID}. */
    @SerialName("RevisionID") val revisionId: String? = null,
    @SerialName("XAttr") val xAttr: String? = null,
    @SerialName("SignatureEmail") val signatureEmail: String? = null,
)

/** Node types per LinkDto.Type (NodeType2 in driveTypes.ts): 1=folder, 2=file. */
object NodeType {
    const val FOLDER = 1
    const val FILE = 2
}

/** Ports the decrypted JSON schema inside Folder.XAttr / File.ActiveRevision.XAttr (extendedAttributes.ts). Only the fields this SDK currently surfaces are modeled. */
@Serializable
data class ExtendedAttributes(@SerialName("Common") val common: ExtendedAttributesCommon? = null)

@Serializable
data class ExtendedAttributesCommon(
    /** ISO 8601. */
    @SerialName("ModificationTime") val modificationTime: String? = null,
    @SerialName("Size") val size: Long? = null,
    /** Original (plaintext) size of each block, in upload order - only ever set when uploading. */
    @SerialName("BlockSizes") val blockSizes: List<Long>? = null,
    /** Only ever set when uploading. */
    @SerialName("Digests") val digests: ExtendedAttributesDigests? = null,
)

@Serializable
data class ExtendedAttributesDigests(
    /** Hex-encoded SHA-1 of the whole plaintext file. */
    @SerialName("SHA1") val sha1: String? = null,
)

/** Ports the request body for POST drive/v2/volumes/{volumeID}/folders. */
@Serializable
data class CreateFolderRequest(
    @SerialName("ParentLinkID") val parentLinkId: String,
    @SerialName("NodeKey") val nodeKey: String,
    @SerialName("NodeHashKey") val nodeHashKey: String,
    @SerialName("NodePassphrase") val nodePassphrase: String,
    @SerialName("NodePassphraseSignature") val nodePassphraseSignature: String,
    @SerialName("SignatureEmail") val signatureEmail: String,
    @SerialName("Name") val name: String,
    @SerialName("Hash") val hash: String,
)

@Serializable
data class CreateFolderResponse(@SerialName("Code") val code: Int, @SerialName("Folder") val folder: CreatedFolderDto)

@Serializable
data class CreatedFolderDto(@SerialName("ID") val id: String)

/** Ports RenameLinkRequestDto - PUT drive/v2/volumes/{volumeID}/links/{linkID}/rename. */
@Serializable
data class RenameRequest(
    @SerialName("Name") val name: String,
    @SerialName("Hash") val hash: String? = null,
    @SerialName("NameSignatureEmail") val nameSignatureEmail: String? = null,
    /** Current name hash before the rename, to prevent races - see LinkDto.NameHash. */
    @SerialName("OriginalHash") val originalHash: String? = null,
)

@Serializable
data class RenameResponse(@SerialName("Code") val code: Int)

/**
 * Ports PostCopyNodeRequest - POST drive/volumes/{volumeID}/links/{linkID}/copy. Note this
 * endpoint has no "v2" prefix, unlike most others. [NodePassphraseSignature]/[SignatureEmail]
 * must be omitted (left `null`) for normal, owned links - the API rejects them with a 422
 * ("A NodePassphraseSignature and a SignatureEmail are required only when moving/copying
 * anonymous Links") otherwise. They only apply to "anonymous" links (nodes from public/
 * anonymous uploads with no owning address), which this SDK doesn't create or otherwise
 * support.
 *
 * Note: `PUT .../move` (the equivalent endpoint for moving rather than copying) is
 * deliberately never called by this SDK - see [DriveClient.moveNode]'s kdoc for why.
 */
@Serializable
data class CopyNodeRequest(
    @SerialName("TargetVolumeID") val targetVolumeId: String,
    @SerialName("TargetParentLinkID") val targetParentLinkId: String,
    @SerialName("NodePassphrase") val nodePassphrase: String,
    @SerialName("NodePassphraseSignature") val nodePassphraseSignature: String? = null,
    @SerialName("SignatureEmail") val signatureEmail: String? = null,
    @SerialName("Name") val name: String,
    @SerialName("NameSignatureEmail") val nameSignatureEmail: String,
    @SerialName("Hash") val hash: String,
)

@Serializable
data class CopyNodeResponse(@SerialName("Code") val code: Int, @SerialName("LinkID") val linkId: String)

/** Ports CreateRevisionRequestDto - POST drive/v2/volumes/{volumeID}/files/{linkID}/revisions. */
@Serializable
data class CreateRevisionRequest(
    @SerialName("CurrentRevisionID") val currentRevisionId: String,
    @SerialName("ClientUID") val clientUid: String? = null,
    @SerialName("IntendedUploadSize") val intendedUploadSize: Long? = null,
)

@Serializable
data class CreateRevisionResponse(@SerialName("Code") val code: Int, @SerialName("Revision") val revision: CreatedRevisionDto)

@Serializable
data class CreatedRevisionDto(@SerialName("ID") val id: String)

/** Ports LinkIDsRequestDto - shared by trash_multiple and similar bulk-by-LinkID endpoints. */
@Serializable
data class LinkIdsRequest(@SerialName("LinkIDs") val linkIds: List<String>)

/** Ports MultiResponsesPerLinkFactory - per-link success/failure reporting for bulk operations. */
@Serializable
data class MultiLinkResponse(@SerialName("Code") val code: Int, @SerialName("Responses") val responses: List<LinkOperationResult> = emptyList())

@Serializable
data class LinkOperationResult(@SerialName("LinkID") val linkId: String, @SerialName("Response") val response: LinkOperationStatus)

@Serializable
data class LinkOperationStatus(@SerialName("Code") val code: Int, @SerialName("Error") val error: String? = null)
