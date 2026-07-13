@file:OptIn(ExperimentalEncodingApi::class, ExperimentalUuidApi::class, ExperimentalStdlibApi::class)

package dev.carlsen.protondrive.sdk.nodes

import dev.carlsen.protondrive.sdk.ProtonDriveTelemetry
import dev.carlsen.protondrive.sdk.account.ResolvedAddress
import dev.carlsen.protondrive.sdk.apiService.DriveAPIService
import dev.carlsen.protondrive.sdk.apiService.isCodeOk
import dev.carlsen.protondrive.sdk.crypto.DigestAlgorithm
import dev.carlsen.protondrive.sdk.crypto.EncryptedDetachedResult
import dev.carlsen.protondrive.sdk.crypto.IncrementalDigest
import dev.carlsen.protondrive.sdk.crypto.OpenPGPCrypto
import dev.carlsen.protondrive.sdk.crypto.PrivateKeyHandle
import dev.carlsen.protondrive.sdk.crypto.PublicKeyHandle
import dev.carlsen.protondrive.sdk.crypto.SessionKeyHandle
import dev.carlsen.protondrive.sdk.crypto.VerifyStatus
import dev.carlsen.protondrive.sdk.crypto.hmacSha256
import dev.carlsen.protondrive.sdk.crypto.sha256
import dev.carlsen.protondrive.sdk.crypto.toPublicKeyHandle
import dev.carlsen.protondrive.sdk.errors.IntegrityError
import dev.carlsen.protondrive.sdk.errors.ProtonDriveError
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** Matches client/js/src/internal/download/apiService.ts's BLOCKS_PAGE_SIZE. */
private const val BLOCKS_PAGE_SIZE = 20

/** Matches client/js/src/internal/upload/streamUploader.ts's FILE_CHUNK_SIZE. */
private const val FILE_CHUNK_SIZE = 4 * 1024 * 1024

/**
 * A pre-generated thumbnail to upload alongside a file's content in [DriveClient.uploadFile].
 * This SDK does no image processing itself - matching the JS SDK's own `Thumbnail` type, the
 * caller decodes/resizes/re-encodes the image and supplies the raw bytes here.
 *
 * @param type 1 = Preview (512px, max 69632 bytes encrypted), 2 = HDPreview (1920px, max
 * 1052672 bytes encrypted), 3 = MachineLearning (not shown in any UI). Values per Proton's API
 * docs for `ThumbnailType`.
 * @param data Plaintext (not yet encrypted) thumbnail bytes - typically a small JPEG.
 */
data class UploadThumbnail(val type: Int, val data: ByteArray)

data class Node(
    val volumeId: String,
    val linkId: String,
    val name: String,
    val type: Int,
    /** Epoch seconds. Best-effort: prefers the decrypted XAttr modification time, falls back to the server's (unencrypted) ModifyTime. */
    val modifiedTime: Long,
    /** Decrypted content size in bytes. Only ever populated for files, and only if XAttr decrypted successfully. */
    val size: Long? = null,
    /** Present only for folders - needed to decrypt this folder's own children or create a node inside it. */
    val key: PrivateKeyHandle? = null,
    /** Present only for folders - needed to compute the lookup Hash when creating a child node. */
    val hashKey: ByteArray? = null,
    /** This node's own current lookup hash (LinkDto.NameHash) - needed as `OriginalHash` when renaming it. */
    val hash: String? = null,
    /** LinkID of this node's parent folder; null for the volume root. */
    val parentLinkId: String? = null,
) {
    val isFolder: Boolean get() = type == NodeType.FOLDER
}

/**
 * Walks and mutates the Drive node tree: bootstraps the user's main
 * ("my-files") volume root, lists folder children, and creates new folders,
 * decrypting/encrypting names, keys, and extended attributes along the way.
 * Ports the relevant slice of client/js/src/internal/nodes/ and
 * internal/shares/ - specifically the bootstrap ("my-files"), children
 * listing, bulk link-loading, and folder-creation endpoints, plus the
 * key/passphrase/name/XAttr crypto sequences from crypto/driveCrypto.ts.
 *
 * Also ports the download slice of internal/download/ (see [downloadFile]).
 *
 * Sharing, upload, and non-root volumes are still out of scope for this MVP
 * slice - see the wider kmp-protondrive roadmap for those.
 */
class DriveClient(
    private val apiService: DriveAPIService,
    private val crypto: OpenPGPCrypto,
    ownAddresses: List<ResolvedAddress>,
    telemetry: ProtonDriveTelemetry,
    /**
     * When true (the default - mirroring cryptoService.ts's verifyBlock), every uploaded block
     * is decrypted right back after encryption to catch corruption/bad hardware before it's
     * committed. Costs a full extra symmetric decryption per 4 MiB block, which is significant
     * on platforms with software-only crypto (Android) - hosts there may opt out.
     */
    private val verifyBlocksBeforeUpload: Boolean = true,
) {
    private val addressesById: Map<String, ResolvedAddress> = ownAddresses.associateBy { it.addressId }
    private val addressKeysByAddressId: Map<String, List<PrivateKeyHandle>> =
        ownAddresses.associate { it.addressId to it.keys }
    private val addressPublicKeysByEmail: Map<String, List<PublicKeyHandle>> =
        ownAddresses.associate { it.email to it.keys.map(PrivateKeyHandle::toPublicKeyHandle) }

    private val logger = telemetry.getLogger("nodes")
    private val json = Json { ignoreUnknownKeys = true }

    /** The address that owns the my-files share, resolved by [getMyFilesRoot] - needed to sign newly created nodes. */
    private var rootAddressId: String? = null

    /** The my-files share key, resolved by [getMyFilesRoot] - decrypts the root folder's own passphrase. */
    private var shareKey: PrivateKeyHandle? = null

    /**
     * Decrypted node keys by "volumeId/linkId", filled by every decryption this client performs.
     * Safe to cache indefinitely: a node's key material never changes - rename/move/copy only
     * re-wrap the passphrase for a different parent, the decrypted key itself is stable.
     * Lets the raw-identifier entry points ([getNode] and friends) resolve a deep node without
     * re-walking and re-decrypting the whole parent chain on every call.
     *
     * Guarded by [nodeKeyCacheMutex]: [listChildren] decrypts sibling nodes concurrently, and a
     * plain mutable map is not safe against parallel writes. Access only via [cachedNodeKey]/
     * [cacheNodeKey].
     */
    private val nodeKeyCache = mutableMapOf<String, PrivateKeyHandle>()
    private val nodeKeyCacheMutex = Mutex()

    private suspend fun cachedNodeKey(volumeId: String, linkId: String): PrivateKeyHandle? =
        nodeKeyCacheMutex.withLock { nodeKeyCache["$volumeId/$linkId"] }

    private suspend fun cacheNodeKey(volumeId: String, linkId: String, key: PrivateKeyHandle) {
        nodeKeyCacheMutex.withLock { nodeKeyCache["$volumeId/$linkId"] = key }
    }

    /** Lazily runs [getMyFilesRoot] so entry points that need the signing address work even if the host never called it. */
    private suspend fun signingAddressId(): String {
        rootAddressId?.let { return it }
        getMyFilesRoot()
        return requireNotNull(rootAddressId) { "my-files bootstrap did not resolve a signing address" }
    }

    /** Lazily runs [getMyFilesRoot] to resolve the share key - the "parent key" of the volume root. */
    private suspend fun myFilesShareKey(): PrivateKeyHandle {
        shareKey?.let { return it }
        getMyFilesRoot()
        return requireNotNull(shareKey) { "my-files bootstrap did not resolve the share key" }
    }

    suspend fun getMyFilesRoot(): Node {
        val bootstrap = apiService.get<PrimaryRootShareResponse>("drive/v2/shares/my-files")
        val share = bootstrap.share
        val addressKeys = addressKeysByAddressId[share.addressId]
            ?: throw ProtonDriveError("No decrypted address key available for share AddressID ${share.addressId}")
        val creatorPublicKeys = addressPublicKeysByEmail[share.creatorEmail].orEmpty()
        rootAddressId = share.addressId

        val shareKey = decryptNodeOrShareKey(
            armoredKey = share.key,
            armoredPassphrase = share.passphrase,
            armoredPassphraseSignature = share.passphraseSignature,
            decryptionKeys = addressKeys,
            verificationKeys = creatorPublicKeys,
        )
        this.shareKey = shareKey

        // The root folder's own link details come back inline - no follow-up load needed.
        return decryptLinkDetails(bootstrap.volume.volumeId, bootstrap.link, parentKey = shareKey)
    }

    /**
     * Fetches and decrypts a single node by its raw identifiers, without listing its parent's
     * contents - for hosts that persisted only a `volumeId`/`linkId` pair (e.g. across app
     * restarts) rather than holding onto a [Node]. Resolves the decryption keys by walking the
     * parent chain up to the my-files root, caching each decrypted key so repeated lookups
     * (and the other raw-identifier overloads, which are all built on this) don't re-fetch or
     * re-decrypt ancestors. When you already hold a decrypted [Node], prefer the Node-taking
     * overloads - they skip these extra link loads entirely.
     */
    suspend fun getNode(volumeId: String, linkId: String): Node {
        val details = loadLinks(volumeId, listOf(linkId)).firstOrNull()
            ?: throw ProtonDriveError("Node $linkId not found in volume $volumeId")
        return decryptLinkDetails(volumeId, details, parentKeyFor(volumeId, details.link.parentLinkId))
    }

    /** The key that decrypts a child of [parentLinkId]: the parent's own node key, or the share key at the volume root. */
    private suspend fun parentKeyFor(volumeId: String, parentLinkId: String?): PrivateKeyHandle =
        if (parentLinkId != null) resolveNodeKey(volumeId, parentLinkId) else myFilesShareKey()

    /** Resolves (fetch + decrypt, or cache hit) a node's own key, recursing up the parent chain as needed. */
    private suspend fun resolveNodeKey(volumeId: String, linkId: String): PrivateKeyHandle {
        cachedNodeKey(volumeId, linkId)?.let { return it }
        val link = loadLinks(volumeId, listOf(linkId)).firstOrNull()?.link
            ?: throw ProtonDriveError("Node $linkId not found in volume $volumeId")
        val parentKey = parentKeyFor(volumeId, link.parentLinkId)
        val keyVerificationKeys = addressPublicKeysByEmail[link.signatureEmail].orEmpty()
        val nodeKey = decryptNodeOrShareKey(link.nodeKey, link.nodePassphrase, link.nodePassphraseSignature, listOf(parentKey), keyVerificationKeys)
        cacheNodeKey(volumeId, linkId, nodeKey)
        return nodeKey
    }

    suspend fun listChildren(parent: Node): List<Node> {
        val parentKey = requireNotNull(parent.key) { "Cannot list children of a non-folder node (${parent.linkId})" }

        val linkIds = mutableListOf<String>()
        var anchor: String? = null
        while (true) {
            val query = "drive/v2/volumes/${parent.volumeId}/folders/${parent.linkId}/children" +
                if (anchor != null) "?AnchorID=$anchor" else ""
            val page = apiService.get<ListChildrenResponse>(query)
            linkIds += page.linkIds
            if (!page.more || page.anchorId == null) break
            anchor = page.anchorId
        }
        if (linkIds.isEmpty()) return emptyList()

        val loaded = loadLinks(parent.volumeId, linkIds)
        // A single sibling this SDK can't decrypt (e.g. corrupted/orphaned debris from an
        // earlier interrupted operation) must not take down the whole listing, and must not
        // be silently hidden either - a hidden-but-still-server-side-present node can still
        // block a same-named upload/move/copy into this folder with a confusing "already
        // exists" error, with no way to find and delete the culprit. So it's surfaced as a
        // clearly-marked placeholder instead: undecryptable but still selectable for
        // trashNode() (which needs only volumeId/linkId, no decryption). Logged with enough
        // of the raw (still-encrypted) field to diagnose - the ciphertext isn't sensitive.
        //
        // Siblings are decrypted concurrently on Dispatchers.Default: each node costs several
        // independent PGP operations, so this scales with cores - which matters most on
        // Android, where the per-operation crypto is slowest.
        return coroutineScope {
            loaded.map { details ->
                async(Dispatchers.Default) {
                    runCatching { decryptLinkDetails(parent.volumeId, details, parentKey) }
                        .getOrElse { error ->
                            val link = details.link
                            logger.warn(
                                "Failed to decrypt node ${link.linkId}: ${error::class.simpleName}: ${error.message}\n" +
                                    "Name (${link.name.length} chars): ${link.name}\n" +
                                    "NodePassphrase (${link.nodePassphrase.length} chars): ${link.nodePassphrase}\n" +
                                    "NodePassphraseSignature (${link.nodePassphraseSignature.length} chars): ${link.nodePassphraseSignature}",
                            )
                            Node(
                                volumeId = parent.volumeId,
                                linkId = link.linkId,
                                name = "<undecryptable: ${link.linkId.take(12)}…>",
                                type = link.type,
                                modifiedTime = link.modifyTime,
                                parentLinkId = parent.linkId,
                            )
                        }
                }
            }.awaitAll()
        }
    }

    /** [listChildren] variant taking raw identifiers instead of a [Node] - see [getNode]. */
    suspend fun listChildren(volumeId: String, folderLinkId: String): List<Node> =
        listChildren(getNode(volumeId, folderLinkId))

    /** Creates a new folder inside [parent], returning it fully decrypted (ready to navigate into or list). */
    suspend fun createFolder(parent: Node, name: String): Node {
        val parentKey = requireNotNull(parent.key) { "Cannot create a folder inside a non-folder node (${parent.linkId})" }
        val parentHashKey = requireNotNull(parent.hashKey) { "Parent folder's hash key is not available (${parent.linkId})" }
        val addressId = signingAddressId()
        val signingKey = addressKeysByAddressId[addressId]?.firstOrNull()
            ?: throw ProtonDriveError("No usable signing key for address $addressId")
        val signingEmail = addressesById[addressId]?.email
            ?: throw ProtonDriveError("No email on file for address $addressId")

        val folderPassphrase = crypto.generatePassphrase()
        val generatedKey = crypto.generateKey(folderPassphrase)
        val encryptedPassphrase = crypto.encryptAndSignDetachedArmored(
            folderPassphrase.toByteArray(Charsets.UTF_8),
            listOf(parentKey.toPublicKeyHandle()),
            signingKey,
        )

        val hashKeyMaterial = crypto.generatePassphrase().toByteArray(Charsets.UTF_8)
        val armoredHashKey = crypto.encryptAndSignArmored(
            hashKeyMaterial,
            listOf(generatedKey.privateKey.toPublicKeyHandle()),
            generatedKey.privateKey,
        )

        val armoredName = crypto.encryptAndSignArmored(name.toByteArray(Charsets.UTF_8), listOf(parentKey.toPublicKeyHandle()), signingKey)
        val hash = lookupHash(name, parentHashKey)

        val request = CreateFolderRequest(
            parentLinkId = parent.linkId,
            nodeKey = generatedKey.armoredKey,
            nodeHashKey = armoredHashKey,
            nodePassphrase = encryptedPassphrase.armoredData,
            nodePassphraseSignature = encryptedPassphrase.armoredSignature,
            signatureEmail = signingEmail,
            name = armoredName,
            hash = hash,
        )
        val response = apiService.post<CreateFolderRequest, CreateFolderResponse>(
            "drive/v2/volumes/${parent.volumeId}/folders",
            request,
        )

        return Node(
            volumeId = parent.volumeId,
            linkId = response.folder.id,
            name = name,
            type = NodeType.FOLDER,
            modifiedTime = Clock.System.now().epochSeconds,
            key = generatedKey.privateKey,
            hashKey = hashKeyMaterial,
            hash = hash,
            parentLinkId = parent.linkId,
        ).also { cacheNodeKey(parent.volumeId, it.linkId, generatedKey.privateKey) }
    }

    /** [createFolder] variant taking raw identifiers instead of a [Node] - see [getNode]. */
    suspend fun createFolder(volumeId: String, parentLinkId: String, name: String): Node =
        createFolder(getNode(volumeId, parentLinkId), name)

    /** Renames or moves-within-the-same-parent [node]; [parent] must be its current parent folder. Works for files and folders alike. */
    suspend fun renameNode(node: Node, parent: Node, newName: String): Node {
        val parentKey = requireNotNull(parent.key) { "Cannot rename inside a non-folder node (${parent.linkId})" }
        val parentHashKey = requireNotNull(parent.hashKey) { "Parent folder's hash key is not available (${parent.linkId})" }
        val addressId = signingAddressId()
        val signingKey = addressKeysByAddressId[addressId]?.firstOrNull()
            ?: throw ProtonDriveError("No usable signing key for address $addressId")
        val signingEmail = addressesById[addressId]?.email
            ?: throw ProtonDriveError("No email on file for address $addressId")

        val armoredName = crypto.encryptAndSignArmored(newName.toByteArray(Charsets.UTF_8), listOf(parentKey.toPublicKeyHandle()), signingKey)
        val newHash = lookupHash(newName, parentHashKey)

        apiService.put<RenameRequest, RenameResponse>(
            "drive/v2/volumes/${node.volumeId}/links/${node.linkId}/rename",
            RenameRequest(name = armoredName, hash = newHash, nameSignatureEmail = signingEmail, originalHash = node.hash),
        )

        return node.copy(name = newName, hash = newHash)
    }

    /** [renameNode] variant taking raw identifiers instead of [Node]s - resolves the current parent itself; see [getNode]. */
    suspend fun renameNode(volumeId: String, linkId: String, newName: String): Node {
        val node = getNode(volumeId, linkId)
        val parentLinkId = requireNotNull(node.parentLinkId) { "Cannot rename the volume root ($linkId)" }
        return renameNode(node, getNode(volumeId, parentLinkId), newName)
    }

    /** Moves [node] to trash (soft delete - recoverable, matches Proton's own clients' default "delete" behavior). */
    suspend fun trashNode(node: Node) = trashNode(node.volumeId, node.linkId, displayName = node.name)

    /** [trashNode] variant taking raw identifiers instead of a [Node] - trashing needs no decryption, so this makes no extra requests. */
    suspend fun trashNode(volumeId: String, linkId: String) = trashNode(volumeId, linkId, displayName = linkId)

    private suspend fun trashNode(volumeId: String, linkId: String, displayName: String) {
        val response = apiService.post<LinkIdsRequest, MultiLinkResponse>(
            "drive/v2/volumes/$volumeId/trash_multiple",
            LinkIdsRequest(linkIds = listOf(linkId)),
        )
        val result = response.responses.firstOrNull { it.linkId == linkId }
            ?: throw ProtonDriveError("Trash request for \"$displayName\" returned no result")
        if (!isCodeOk(result.response.code)) {
            throw ProtonDriveError("Failed to move \"$displayName\" to trash: ${result.response.error ?: "code ${result.response.code}"}")
        }
    }

    /**
     * Moves [node] - a **file only** - from [oldParent] to [newParent], implemented as
     * [copyNode] followed by [trashNode] of the original rather than a direct call to
     * Proton's `PUT .../move` endpoint. That endpoint was found (confirmed against a real
     * account, including ruling out a read-after-write timing race via a retry-with-backoff
     * probe) to permanently corrupt the moved file's passphrase - `copyNode`, a different
     * endpoint sharing the same crypto/request-construction code, has never shown this
     * problem. Folders have no such fallback (`copyNode` is files-only) and so aren't
     * supported at all here until the underlying move endpoint is fixed.
     */
    suspend fun moveNode(node: Node, oldParent: Node, newParent: Node): Node {
        require(!node.isFolder) {
            "Moving folders is not supported (${node.linkId}) - Proton's move endpoint has a confirmed " +
                "data-corruption bug with no safe workaround for folders (copyNode, the fallback used for files, " +
                "is files-only)"
        }
        val copied = copyNode(node, oldParent, newParent, node.name)
        trashNode(node)
        return copied
    }

    /** [moveNode] variant taking raw identifiers instead of [Node]s - resolves the node and both parents itself; see [getNode]. */
    suspend fun moveNode(volumeId: String, linkId: String, newParentLinkId: String): Node {
        val node = getNode(volumeId, linkId)
        val oldParentLinkId = requireNotNull(node.parentLinkId) { "Cannot move the volume root ($linkId)" }
        return moveNode(node, getNode(volumeId, oldParentLinkId), getNode(volumeId, newParentLinkId))
    }

    /**
     * Copies [node] - a **file only** (a shallow copy of a folder would create an empty
     * folder sharing the same keys, not a deep copy of its contents, so this isn't offered
     * for folders) - from [currentParent] into [newParent], optionally under [newName],
     * returning the new node. The copy reuses the same node key and content (including its
     * ContentKeyPacket) as the original - only the name and passphrase are re-wrapped for
     * [newParent]'s key, so no file content is re-uploaded. Same calling convention as
     * [moveNode]. Ports nodesManagement.ts's `copyNode()`.
     */
    suspend fun copyNode(node: Node, currentParent: Node, newParent: Node, newName: String = node.name): Node {
        require(!node.isFolder) { "Copying folders is not supported (${node.linkId}) - only files can be copied" }
        val currentParentKey = requireNotNull(currentParent.key) { "Current parent folder's key is not available (${currentParent.linkId})" }
        val newParentKey = requireNotNull(newParent.key) { "New parent folder's key is not available (${newParent.linkId})" }
        val newParentHashKey = requireNotNull(newParent.hashKey) { "New parent folder's hash key is not available (${newParent.linkId})" }
        val addressId = signingAddressId()
        val signingKey = addressKeysByAddressId[addressId]?.firstOrNull()
            ?: throw ProtonDriveError("No usable signing key for address $addressId")
        val signingEmail = addressesById[addressId]?.email
            ?: throw ProtonDriveError("No email on file for address $addressId")

        val details = loadLinks(node.volumeId, listOf(node.linkId)).firstOrNull()
            ?: throw ProtonDriveError("Node ${node.linkId} not found")
        val link = details.link
        // Critical safety check - see moveNode's kdoc/comment: decrypting with a stale parent
        // key doesn't necessarily throw, it can silently produce garbage that then gets
        // re-encrypted and written back, corrupting the node.
        if (link.parentLinkId != currentParent.linkId) {
            throw ProtonDriveError(
                "\"${node.name}\"'s parent has changed since it was selected (expected ${currentParent.linkId}, " +
                    "actually ${link.parentLinkId}) - refresh and try again",
            )
        }
        val keyVerificationKeys = addressPublicKeysByEmail[link.signatureEmail].orEmpty()
        val passphrase = decryptPassphrase(link.nodePassphrase, link.nodePassphraseSignature, listOf(currentParentKey), keyVerificationKeys)

        val newParentPublicKey = newParentKey.toPublicKeyHandle()
        val armoredName = crypto.encryptAndSignArmored(newName.toByteArray(Charsets.UTF_8), listOf(newParentPublicKey), signingKey)
        verifyReencryptedNameOrThrow(newName, armoredName, newParentKey)
        val newHash = lookupHash(newName, newParentHashKey)
        val encryptedPassphrase = crypto.encryptAndSignDetachedArmored(passphrase.toByteArray(Charsets.UTF_8), listOf(newParentPublicKey), signingKey)
        verifyReencryptedPassphraseOrThrow(node.name, encryptedPassphrase, newParentKey, signingKey, passphrase)

        val response = apiService.post<CopyNodeRequest, CopyNodeResponse>(
            "drive/volumes/${node.volumeId}/links/${node.linkId}/copy",
            CopyNodeRequest(
                targetVolumeId = newParent.volumeId,
                targetParentLinkId = newParent.linkId,
                // NodePassphraseSignature/SignatureEmail deliberately omitted - see CopyNodeRequest's kdoc.
                nodePassphrase = encryptedPassphrase.armoredData,
                name = armoredName,
                nameSignatureEmail = signingEmail,
                hash = newHash,
            ),
        )

        return node.copy(linkId = response.linkId, name = newName, hash = newHash, parentLinkId = newParent.linkId)
    }

    /** [copyNode] variant taking raw identifiers instead of [Node]s - resolves the node and both parents itself; see [getNode]. */
    suspend fun copyNode(volumeId: String, linkId: String, newParentLinkId: String, newName: String? = null): Node {
        val node = getNode(volumeId, linkId)
        val currentParentLinkId = requireNotNull(node.parentLinkId) { "Cannot copy the volume root ($linkId)" }
        return copyNode(node, getNode(volumeId, currentParentLinkId), getNode(volumeId, newParentLinkId), newName ?: node.name)
    }

    /**
     * Downloads and decrypts [node]'s active revision content, writing the
     * plaintext bytes to [sink] as they're verified. [parent] must be its
     * current parent folder (same calling convention as [renameNode]).
     *
     * Ports client/js/src/internal/download/'s apiService.ts/cryptoService.ts:
     * re-fetches the node's crypto material fresh (rather than trusting a
     * possibly-stale cached [Node]), decrypts the file's content session key
     * from its ContentKeyPacket, then streams each 4 MiB block - verifying
     * each block's SHA-256 hash and, once every block is consumed, the
     * revision's overall manifest signature (concatenation of every
     * thumbnail's hash, then every block's hash - thumbnail content itself
     * isn't downloaded, but its hash is still part of the signed manifest).
     * A manifest failure is a hard error: unlike XAttr metadata, this is the
     * actual file-content integrity guarantee.
     *
     * Does not close [sink] - same "host owns the resource" rule this SDK
     * already applies to sessions; the caller is responsible for closing it.
     */
    suspend fun downloadFile(
        node: Node,
        parent: Node,
        sink: Sink,
        onProgress: ((downloadedBytes: Long) -> Unit)? = null,
    ) {
        require(!node.isFolder) { "Cannot download a folder (${node.linkId}) - only files have content" }
        val parentKey = requireNotNull(parent.key) { "Parent folder's key is not available (${parent.linkId})" }

        val details = loadLinks(node.volumeId, listOf(node.linkId)).firstOrNull()
            ?: throw ProtonDriveError("Node ${node.linkId} not found")
        val link = details.link
        val file = requireNotNull(details.file) { "Node ${node.linkId} is not a file" }

        val keyVerificationKeys = addressPublicKeysByEmail[link.signatureEmail].orEmpty()
        val nodeKey = decryptNodeOrShareKey(link.nodeKey, link.nodePassphrase, link.nodePassphraseSignature, listOf(parentKey), keyVerificationKeys)

        val sessionKey = decryptContentSessionKey(file, nodeKey)

        val revisionId = requireNotNull(file.activeRevision?.revisionId) { "File ${node.linkId} has no active revision" }
        val revisionVerificationKeys = addressPublicKeysByEmail[file.activeRevision.signatureEmail ?: link.signatureEmail]
            .orEmpty()
            .ifEmpty { listOf(nodeKey.toPublicKeyHandle()) }

        var manifestSignature: String? = null
        // The manifest signature covers every thumbnail's hash, then every block's hash, in
        // that order - even though this SDK doesn't download thumbnail content itself.
        val manifestDigests = mutableListOf<ByteArray>()
        var fromBlockIndex = 1
        var downloadedBytes = 0L

        while (true) {
            val page = apiService.get<GetRevisionResponse>(
                "drive/v2/volumes/${node.volumeId}/files/${node.linkId}/revisions/$revisionId" +
                    "?PageSize=$BLOCKS_PAGE_SIZE&FromBlockIndex=$fromBlockIndex",
            )
            if (fromBlockIndex == 1) {
                manifestSignature = page.revision.manifestSignature
                page.revision.thumbnails.forEach { thumbnail -> manifestDigests += Base64.decode(thumbnail.hash) }
            }
            if (page.revision.blocks.isEmpty()) break

            for (block in page.revision.blocks) {
                val url = requireNotNull(block.bareUrl) { "Block ${block.index} of \"${node.name}\" has no download URL" }
                val token = requireNotNull(block.token) { "Block ${block.index} of \"${node.name}\" has no download token" }
                val encrypted = apiService.getBlockStream(url, token)

                val digest = sha256(encrypted)
                val expectedHash = Base64.decode(block.hash)
                if (!digest.contentEquals(expectedHash)) {
                    throw IntegrityError("Block ${block.index} of \"${node.name}\" failed its integrity check")
                }
                manifestDigests += digest

                val plaintext = crypto.decryptWithSessionKey(encrypted, sessionKey).data
                sink.write(plaintext)
                downloadedBytes += plaintext.size
                onProgress?.invoke(downloadedBytes)

                fromBlockIndex = block.index + 1
            }
        }
        sink.flush()

        val signature = manifestSignature ?: throw IntegrityError("\"${node.name}\" is missing its integrity signature")
        val manifest = manifestDigests.fold(ByteArray(0)) { acc, digest -> acc + digest }
        val manifestVerify = crypto.verifyArmoredDetached(manifest, signature, revisionVerificationKeys)
        if (manifestVerify.verified != VerifyStatus.OK) {
            throw IntegrityError("\"${node.name}\" failed its file integrity check (invalid manifest signature)")
        }
    }

    /** [downloadFile] variant taking raw identifiers instead of [Node]s - resolves the file and its parent itself; see [getNode]. */
    suspend fun downloadFile(
        volumeId: String,
        linkId: String,
        sink: Sink,
        onProgress: ((downloadedBytes: Long) -> Unit)? = null,
    ) {
        val node = getNode(volumeId, linkId)
        val parentLinkId = requireNotNull(node.parentLinkId) { "Cannot download the volume root ($linkId)" }
        downloadFile(node, getNode(volumeId, parentLinkId), sink, onProgress)
    }

    /**
     * Uploads [source]'s content as a brand-new file named [name] inside [parent], returning
     * it fully decrypted (ready to list/rename/download). Ports the relevant slice of
     * client/js/src/internal/upload/'s apiService.ts/cryptoService.ts/streamUploader.ts,
     * scoped to creating a new file (not new revisions of existing files), and reading the
     * content sequentially rather than JS's concurrent multi-block pipeline - a CLI has no
     * need for that complexity.
     *
     * 1. Generates a new node key/passphrase/content-session-key, same shape as [createFolder].
     * 2. Creates a draft file (`POST .../files`), then fetches this draft's per-revision
     *    VerificationCode (`GET .../verification`) - a random value the server later checks
     *    each block's [OpenPGPCrypto.decryptWithSessionKey]-XOR proof against, to catch
     *    corruption/bad hardware, not to verify authenticity (Proton's own API docs mark the
     *    per-block `EncSignature` field deprecated and no longer read by any client - this
     *    SDK doesn't send one).
     * 3. If [thumbnails] are given (the caller generates these - this SDK doesn't do image
     *    processing, matching the JS SDK's own `Thumbnail[]` parameter, which the host web/
     *    mobile app populates), encrypts and uploads each one via its own `POST drive/blocks`
     *    call with an empty `BlockList` - simpler than JS's approach of batching them with the
     *    first content block, at the cost of one extra request.
     * 4. Streams [source] in 4 MiB chunks: encrypts each with the content session key,
     *    requests an upload URL+token (`POST drive/blocks`), and PUTs the encrypted bytes -
     *    which (unlike every other request in this SDK) the storage backend expects as
     *    `multipart/form-data`, matching apiService.ts's `uploadBlock()`.
     * 5. Commits the revision (`PUT .../revisions/{id}`) with a manifest signature (over the
     *    concatenation of every thumbnail's, then every block's, encrypted-bytes SHA-256
     *    digest - mirroring [downloadFile]'s verification the other direction) and XAttr
     *    (size, per-block plaintext sizes, and a whole-file SHA-1 digest).
     *
     * Does not close [source] - same "host owns the resource" rule this SDK already applies
     * to sessions and [downloadFile]'s sink; the caller is responsible for closing it.
     */
    suspend fun uploadFile(
        parent: Node,
        name: String,
        source: Source,
        mediaType: String = "application/octet-stream",
        modificationTime: Instant = Clock.System.now(),
        thumbnails: List<UploadThumbnail> = emptyList(),
        onProgress: ((uploadedBytes: Long) -> Unit)? = null,
    ): Node {
        require(parent.isFolder) { "Cannot upload into a non-folder node (${parent.linkId})" }
        val parentKey = requireNotNull(parent.key) { "Parent folder's key is not available (${parent.linkId})" }
        val parentHashKey = requireNotNull(parent.hashKey) { "Parent folder's hash key is not available (${parent.linkId})" }
        val addressId = signingAddressId()
        val signingKey = addressKeysByAddressId[addressId]?.firstOrNull()
            ?: throw ProtonDriveError("No usable signing key for address $addressId")
        val signingEmail = addressesById[addressId]?.email
            ?: throw ProtonDriveError("No email on file for address $addressId")

        val nodePassphrase = crypto.generatePassphrase()
        val generatedKey = crypto.generateKey(nodePassphrase)
        val nodeKey = generatedKey.privateKey
        val nodePublicKey = nodeKey.toPublicKeyHandle()
        val encryptedPassphrase = crypto.encryptAndSignDetachedArmored(
            nodePassphrase.toByteArray(Charsets.UTF_8),
            listOf(parentKey.toPublicKeyHandle()),
            signingKey,
        )
        val armoredName = crypto.encryptAndSignArmored(name.toByteArray(Charsets.UTF_8), listOf(parentKey.toPublicKeyHandle()), signingKey)
        val hash = lookupHash(name, parentHashKey)

        val sessionKey = crypto.generateSessionKey()
        val contentKeyPacket = Base64.encode(crypto.encryptSessionKey(sessionKey, listOf(nodePublicKey)))
        val contentKeyPacketSignature = crypto.signArmoredDetached(sessionKey.rawBytes, nodeKey)

        val createResponse = apiService.post<CreateFileRequest, CreateFileResponse>(
            "drive/v2/volumes/${parent.volumeId}/files",
            CreateFileRequest(
                parentLinkId = parent.linkId,
                name = armoredName,
                hash = hash,
                mimeType = mediaType,
                nodeKey = generatedKey.armoredKey,
                nodePassphrase = encryptedPassphrase.armoredData,
                nodePassphraseSignature = encryptedPassphrase.armoredSignature,
                contentKeyPacket = contentKeyPacket,
                contentKeyPacketSignature = contentKeyPacketSignature,
                signatureAddress = signingEmail,
            ),
        )
        val linkId = createResponse.file.id
        val revisionId = createResponse.file.revisionId

        val totalSize = uploadRevisionContent(
            volumeId = parent.volumeId,
            linkId = linkId,
            revisionId = revisionId,
            addressId = addressId,
            signingKey = signingKey,
            signingEmail = signingEmail,
            sessionKey = sessionKey,
            nodePublicKey = nodePublicKey,
            source = source,
            thumbnails = thumbnails,
            modificationTime = modificationTime,
            onProgress = onProgress,
        )

        return Node(
            volumeId = parent.volumeId,
            linkId = linkId,
            name = name,
            type = NodeType.FILE,
            modifiedTime = modificationTime.epochSeconds,
            size = totalSize,
            hash = hash,
            parentLinkId = parent.linkId,
        ).also { cacheNodeKey(parent.volumeId, linkId, nodeKey) }
    }

    /** [uploadFile] variant taking raw identifiers instead of a [Node] - see [getNode]. */
    suspend fun uploadFile(
        volumeId: String,
        parentLinkId: String,
        name: String,
        source: Source,
        mediaType: String = "application/octet-stream",
        modificationTime: Instant = Clock.System.now(),
        thumbnails: List<UploadThumbnail> = emptyList(),
        onProgress: ((uploadedBytes: Long) -> Unit)? = null,
    ): Node = uploadFile(getNode(volumeId, parentLinkId), name, source, mediaType, modificationTime, thumbnails, onProgress)

    /**
     * Uploads [source]'s content as a new revision of the *existing* file [node] (inside
     * [parent]), replacing its content while keeping the same node key, content session key,
     * and name - unlike [uploadFile], which creates a brand-new file. Shares essentially all
     * of its block-streaming/manifest/XAttr logic (see [uploadRevisionContent]); the
     * differences are: reusing the existing file's key/content-session-key (decrypted from
     * its current ContentKeyPacket, the same way [downloadFile] does) instead of generating
     * new ones, and creating a new *revision* (`POST .../files/{id}/revisions` with
     * `CurrentRevisionID`) rather than a new file. Ports manager.ts's `createDraftRevision()`.
     */
    suspend fun uploadRevision(
        node: Node,
        parent: Node,
        source: Source,
        modificationTime: Instant = Clock.System.now(),
        thumbnails: List<UploadThumbnail> = emptyList(),
        onProgress: ((uploadedBytes: Long) -> Unit)? = null,
    ): Node {
        require(!node.isFolder) { "Cannot upload a revision to a folder (${node.linkId})" }
        val parentKey = requireNotNull(parent.key) { "Parent folder's key is not available (${parent.linkId})" }
        val addressId = signingAddressId()
        val signingKey = addressKeysByAddressId[addressId]?.firstOrNull()
            ?: throw ProtonDriveError("No usable signing key for address $addressId")
        val signingEmail = addressesById[addressId]?.email
            ?: throw ProtonDriveError("No email on file for address $addressId")

        val details = loadLinks(node.volumeId, listOf(node.linkId)).firstOrNull()
            ?: throw ProtonDriveError("Node ${node.linkId} not found")
        val link = details.link
        // Safety check - see moveNode's kdoc: [parent] is whatever the caller last observed,
        // which can be stale.
        if (link.parentLinkId != parent.linkId) {
            throw ProtonDriveError(
                "\"${node.name}\"'s parent has changed since it was selected (expected ${parent.linkId}, " +
                    "actually ${link.parentLinkId}) - refresh and try again",
            )
        }
        val file = requireNotNull(details.file) { "Node ${node.linkId} is not a file" }
        val keyVerificationKeys = addressPublicKeysByEmail[link.signatureEmail].orEmpty()
        val nodeKey = decryptNodeOrShareKey(link.nodeKey, link.nodePassphrase, link.nodePassphraseSignature, listOf(parentKey), keyVerificationKeys)
        val nodePublicKey = nodeKey.toPublicKeyHandle()
        val sessionKey = decryptContentSessionKey(file, nodeKey)

        val currentRevisionId = requireNotNull(file.activeRevision?.revisionId) { "File ${node.linkId} has no active revision" }
        val createResponse = apiService.post<CreateRevisionRequest, CreateRevisionResponse>(
            "drive/v2/volumes/${node.volumeId}/files/${node.linkId}/revisions",
            CreateRevisionRequest(currentRevisionId = currentRevisionId),
        )
        val revisionId = createResponse.revision.id

        val totalSize = uploadRevisionContent(
            volumeId = node.volumeId,
            linkId = node.linkId,
            revisionId = revisionId,
            addressId = addressId,
            signingKey = signingKey,
            signingEmail = signingEmail,
            sessionKey = sessionKey,
            nodePublicKey = nodePublicKey,
            source = source,
            thumbnails = thumbnails,
            modificationTime = modificationTime,
            onProgress = onProgress,
        )

        return node.copy(size = totalSize, modifiedTime = modificationTime.epochSeconds)
    }

    /** [uploadRevision] variant taking raw identifiers instead of [Node]s - resolves the file and its parent itself; see [getNode]. */
    suspend fun uploadRevision(
        volumeId: String,
        linkId: String,
        source: Source,
        modificationTime: Instant = Clock.System.now(),
        thumbnails: List<UploadThumbnail> = emptyList(),
        onProgress: ((uploadedBytes: Long) -> Unit)? = null,
    ): Node {
        val node = getNode(volumeId, linkId)
        val parentLinkId = requireNotNull(node.parentLinkId) { "Cannot upload a revision to the volume root ($linkId)" }
        return uploadRevision(node, getNode(volumeId, parentLinkId), source, modificationTime, thumbnails, onProgress)
    }

    /**
     * Shared by [uploadFile] and [uploadRevision]: fetches the revision's VerificationCode,
     * uploads any thumbnails, streams [source] in 4 MiB blocks (encrypt, request an upload
     * URL+token, PUT as `multipart/form-data`), then commits the revision with a manifest
     * signature and XAttr. Returns the total plaintext content size.
     */
    private suspend fun uploadRevisionContent(
        volumeId: String,
        linkId: String,
        revisionId: String,
        addressId: String,
        signingKey: PrivateKeyHandle,
        signingEmail: String,
        sessionKey: SessionKeyHandle,
        nodePublicKey: PublicKeyHandle,
        source: Source,
        thumbnails: List<UploadThumbnail>,
        modificationTime: Instant,
        onProgress: ((uploadedBytes: Long) -> Unit)?,
    ): Long {
        val verificationData = apiService.get<VerificationDataResponse>(
            "drive/v2/volumes/$volumeId/links/$linkId/revisions/$revisionId/verification",
        )
        val verificationCode = Base64.decode(verificationData.verificationCode)

        val thumbnailDigests = mutableListOf<ByteArray>()
        if (thumbnails.isNotEmpty()) {
            val encryptedThumbnails = thumbnails.map { it.type to crypto.encryptWithSessionKey(it.data, sessionKey) }
            val thumbnailUploadTokens = apiService.post<RequestUploadRequest, RequestUploadResponse>(
                "drive/blocks",
                RequestUploadRequest(
                    linkId = linkId,
                    revisionId = revisionId,
                    addressId = addressId,
                    volumeId = volumeId,
                    blockList = emptyList(),
                    thumbnailList = encryptedThumbnails.map { (type, _) -> RequestUploadThumbnail(type = type) },
                ),
            )
            for ((type, encryptedThumbnail) in encryptedThumbnails) {
                val link = thumbnailUploadTokens.thumbnailLinks.firstOrNull { it.thumbnailType == type }
                    ?: throw ProtonDriveError("No upload URL returned for thumbnail type $type")
                thumbnailDigests += sha256(encryptedThumbnail)
                val (contentType, multipartBody) = buildMultipartBody("Block", "blob", encryptedThumbnail)
                apiService.postBlockStream(link.bareUrl, link.token, multipartBody, contentType)
            }
        }

        val sha1Digest = IncrementalDigest(DigestAlgorithm.SHA1)
        val blockSizes = mutableListOf<Long>()
        val manifestDigests = mutableListOf<ByteArray>()
        var totalSize = 0L
        var uploadedBytes = 0L
        var blockIndex = 0

        while (true) {
            val chunk = readNextChunk(source, FILE_CHUNK_SIZE) ?: break
            blockIndex++
            sha1Digest.update(chunk)
            totalSize += chunk.size
            blockSizes += chunk.size.toLong()

            val encryptedBlock = crypto.encryptWithSessionKey(chunk, sessionKey)
            // Detect corruption/bad hardware before uploading, mirroring cryptoService.ts's verifyBlock - we
            // discard the result, we just want decryption to throw if something's wrong.
            if (verifyBlocksBeforeUpload) crypto.decryptWithSessionKey(encryptedBlock, sessionKey)

            val verificationToken = ByteArray(verificationCode.size) { i ->
                (verificationCode[i].toInt() xor encryptedBlock.getOrElse(i) { 0 }.toInt()).toByte()
            }

            val uploadTokens = apiService.post<RequestUploadRequest, RequestUploadResponse>(
                "drive/blocks",
                RequestUploadRequest(
                    linkId = linkId,
                    revisionId = revisionId,
                    addressId = addressId,
                    volumeId = volumeId,
                    blockList = listOf(
                        RequestUploadBlock(index = blockIndex, verifier = VerifierDto(Base64.encode(verificationToken))),
                    ),
                ),
            )
            val uploadLink = uploadTokens.uploadLinks.firstOrNull { it.index == blockIndex }
                ?: throw ProtonDriveError("No upload URL returned for block $blockIndex")

            manifestDigests += sha256(encryptedBlock)

            val (contentType, multipartBody) = buildMultipartBody("Block", "blob", encryptedBlock)
            apiService.postBlockStream(uploadLink.bareUrl, uploadLink.token, multipartBody, contentType)
            // Reported per-block (like downloadFile's progress), not per-HTTP-call - the
            // transport's own progress callback isn't wired up to real byte counts (same as
            // postBlockStream's existing callers), so this is the granularity actually available.
            uploadedBytes += chunk.size
            onProgress?.invoke(uploadedBytes)
        }

        val manifest = (thumbnailDigests + manifestDigests).fold(ByteArray(0)) { acc, digest -> acc + digest }
        val manifestSignature = crypto.signArmoredDetached(manifest, signingKey)

        val extendedAttributes = ExtendedAttributes(
            common = ExtendedAttributesCommon(
                modificationTime = modificationTime.toString(),
                size = totalSize,
                blockSizes = blockSizes,
                digests = ExtendedAttributesDigests(sha1 = sha1Digest.digest().toHexString()),
            ),
        )
        val armoredXAttr = crypto.encryptAndSignArmored(
            json.encodeToString(extendedAttributes).toByteArray(Charsets.UTF_8),
            listOf(nodePublicKey),
            signingKey,
        )

        apiService.put<CommitRevisionRequest, CommitRevisionResponse>(
            "drive/v2/volumes/$volumeId/files/$linkId/revisions/$revisionId",
            CommitRevisionRequest(
                manifestSignature = manifestSignature,
                signatureAddress = signingEmail,
                xAttr = armoredXAttr,
            ),
        )

        return totalSize
    }

    /** Reads up to [maxSize] bytes from [source], or `null` at end of stream. May return fewer than [maxSize] bytes only at the very end of the stream. */
    private fun readNextChunk(source: Source, maxSize: Int): ByteArray? {
        if (source.exhausted()) return null
        val buffer = ByteArray(maxSize)
        var offset = 0
        while (offset < maxSize) {
            val read = source.readAtMostTo(buffer, offset, maxSize)
            if (read == -1) break
            offset += read
            if (source.exhausted()) break
        }
        return if (offset == 0) null else buffer.copyOf(offset)
    }

    /** Builds a single-field multipart/form-data body, matching what a browser's `FormData` with one Blob field serializes to (apiService.ts's `uploadBlock()` sends exactly this). */
    private fun buildMultipartBody(fieldName: String, filename: String, data: ByteArray): Pair<String, ByteArray> {
        val boundary = "ProtonDriveKotlinBoundary${Uuid.random().toHexString()}"
        val prefix = "--$boundary\r\nContent-Disposition: form-data; name=\"$fieldName\"; filename=\"$filename\"\r\n" +
            "Content-Type: application/octet-stream\r\n\r\n"
        val suffix = "\r\n--$boundary--\r\n"
        val body = prefix.toByteArray(Charsets.UTF_8) + data + suffix.toByteArray(Charsets.UTF_8)
        return "multipart/form-data; boundary=$boundary" to body
    }

    /** Decrypts the file's content session key from its ContentKeyPacket, verifying the signature best-effort (matches Proton's own note that legacy accounts may sign this differently). */
    private fun decryptContentSessionKey(file: FileDto, nodeKey: PrivateKeyHandle): SessionKeyHandle {
        val contentKeyPacket = requireNotNull(file.contentKeyPacket) { "File has no ContentKeyPacket" }
        val sessionKey = crypto.decryptSessionKey(Base64.decode(contentKeyPacket), listOf(nodeKey))

        file.contentKeyPacketSignature?.let { armoredSignature ->
            runCatching {
                crypto.verifyArmoredDetached(sessionKey.rawBytes, armoredSignature, listOf(nodeKey.toPublicKeyHandle()))
            }
        }

        return sessionKey
    }

    private suspend fun loadLinks(volumeId: String, linkIds: List<String>): List<LinkDetails> =
        apiService.post<LoadLinksRequest, LoadLinksResponse>(
            "drive/v2/volumes/$volumeId/links",
            LoadLinksRequest(linkIds),
        ).links

    private suspend fun decryptLinkDetails(volumeId: String, details: LinkDetails, parentKey: PrivateKeyHandle): Node {
        val link = details.link

        val nameVerificationKeys = addressPublicKeysByEmail[link.nameSignatureEmail ?: link.signatureEmail].orEmpty()
        val nameResult = runCatching { crypto.decryptArmoredAndVerify(link.name, listOf(parentKey), nameVerificationKeys) }
            .getOrElse { throw ProtonDriveError("Failed to decrypt Name field for ${link.linkId}: ${it.message}", it) }
        val name = nameResult.data.toString(Charsets.UTF_8)

        val keyVerificationKeys = addressPublicKeysByEmail[link.signatureEmail].orEmpty()
        // Every node's own key is decrypted (not just folders'): files need theirs transiently to
        // decrypt XAttr for size/modification time, even though they have no children to unlock.
        val nodeKey = runCatching {
            decryptNodeOrShareKey(link.nodeKey, link.nodePassphrase, link.nodePassphraseSignature, listOf(parentKey), keyVerificationKeys)
        }.getOrElse { throw ProtonDriveError("Failed to decrypt NodePassphrase/NodeKey field for ${link.linkId}: ${it.message}", it) }
        cacheNodeKey(volumeId, link.linkId, nodeKey)

        val isFolder = link.type == NodeType.FOLDER
        val hashKey = if (isFolder) {
            details.folder?.nodeHashKey?.let { armored ->
                runCatching {
                    crypto.decryptArmoredAndVerify(armored, listOf(nodeKey), listOf(nodeKey.toPublicKeyHandle())).data
                }.getOrNull()
            }
        } else {
            null
        }

        val xattrArmored = details.folder?.xAttr ?: details.file?.activeRevision?.xAttr
        val xattrVerificationKeys = addressPublicKeysByEmail[details.file?.activeRevision?.signatureEmail ?: link.signatureEmail].orEmpty()
        val xattr = decryptExtendedAttributes(xattrArmored, nodeKey, xattrVerificationKeys)
        val modifiedTime = xattr?.common?.modificationTime
            ?.let { runCatching { Instant.parse(it).epochSeconds }.getOrNull() }
            ?: link.modifyTime

        return Node(
            volumeId = volumeId,
            linkId = link.linkId,
            name = name,
            type = link.type,
            modifiedTime = modifiedTime,
            size = xattr?.common?.size,
            key = if (isFolder) nodeKey else null,
            hashKey = hashKey,
            hash = link.nameHash,
            parentLinkId = link.parentLinkId,
        )
    }

    /** Best-effort: a missing/unparsable/unverifiable XAttr shouldn't fail listing over a size/mtime nicety. */
    private fun decryptExtendedAttributes(
        armored: String?,
        nodeKey: PrivateKeyHandle,
        verificationKeys: List<PublicKeyHandle>,
    ): ExtendedAttributes? {
        if (armored == null) return null
        return runCatching {
            val result = crypto.decryptArmoredAndVerify(armored, listOf(nodeKey), verificationKeys)
            json.decodeFromString<ExtendedAttributes>(result.data.toString(Charsets.UTF_8))
        }.getOrNull()
    }

    /** Ports driveCrypto.ts's decryptKey(): decrypt the passphrase's session key, verify+decrypt the passphrase, then unlock the key with it. */
    private fun decryptNodeOrShareKey(
        armoredKey: String,
        armoredPassphrase: String,
        armoredPassphraseSignature: String,
        decryptionKeys: List<PrivateKeyHandle>,
        verificationKeys: List<PublicKeyHandle>,
    ): PrivateKeyHandle {
        val passphrase = decryptPassphrase(armoredPassphrase, armoredPassphraseSignature, decryptionKeys, verificationKeys)
        return crypto.decryptKey(armoredKey, passphrase)
    }

    /** Decrypts a node/share passphrase without unlocking a key with it - needed by [moveNode]/[copyNode], which re-wrap an *existing* passphrase for a new parent rather than unlocking the node's own key. */
    private fun decryptPassphrase(
        armoredPassphrase: String,
        armoredPassphraseSignature: String,
        decryptionKeys: List<PrivateKeyHandle>,
        verificationKeys: List<PublicKeyHandle>,
    ): String {
        val sessionKey = crypto.decryptArmoredSessionKey(armoredPassphrase, decryptionKeys)
        // The detached signature is verified best-effort: a node whose NodePassphrase was
        // re-wrapped by an earlier, now-fixed move/copy bug can be left with a permanently
        // malformed NodePassphraseSignature, since this SDK (correctly, per the API's own
        // "anonymous links only" rule) never rewrites that field on subsequent moves - so a
        // bad signature from the past can never self-heal. Decrypting the passphrase itself
        // only depends on the session key, not on the signature parsing cleanly, so a broken
        // signature shouldn't lock the node out of being read entirely.
        val result = runCatching {
            crypto.decryptArmoredAndVerifyDetached(armoredPassphrase, armoredPassphraseSignature, sessionKey, verificationKeys)
        }.getOrElse {
            logger.warn("Ignoring unparseable/unverifiable NodePassphraseSignature (${it::class.simpleName}: ${it.message}) - decrypting without verification")
            crypto.decryptArmoredAndVerifyDetached(armoredPassphrase, null, sessionKey, verificationKeys)
        }
        return result.data.toString(Charsets.UTF_8)
    }

    /**
     * Diagnostic safety gate for [moveNode]/[copyNode]: decrypts the freshly re-encrypted
     * passphrase right back with [newParentKey] *before* anything is sent to the server, and
     * confirms it matches [expectedPlaintext]. Move/copy have been observed to sometimes
     * produce a NodePassphrase that fails to decrypt later (root cause still under
     * investigation) - this catches that locally instead of writing corrupt data to the
     * server. Logged verbosely on failure to help pin down where the corruption originates.
     */
    private fun verifyReencryptedPassphraseOrThrow(
        nodeName: String,
        encryptedPassphrase: EncryptedDetachedResult,
        newParentKey: PrivateKeyHandle,
        signingKey: PrivateKeyHandle,
        expectedPlaintext: String,
    ) {
        val selfCheck = runCatching {
            decryptPassphrase(
                encryptedPassphrase.armoredData,
                encryptedPassphrase.armoredSignature,
                listOf(newParentKey),
                listOf(signingKey.toPublicKeyHandle()),
            )
        }
        val decrypted = selfCheck.getOrNull()
        if (selfCheck.isFailure || decrypted != expectedPlaintext) {
            logger.error(
                "Self-check failed for \"$nodeName\"'s re-encrypted passphrase before sending - refusing to proceed.\n" +
                    "Expected plaintext length: ${expectedPlaintext.length}, got: ${decrypted?.length}\n" +
                    "Freshly re-encrypted armored data:\n${encryptedPassphrase.armoredData}",
                selfCheck.exceptionOrNull(),
            )
            throw ProtonDriveError(
                "Refusing to write \"$nodeName\": the freshly re-encrypted passphrase failed to verify locally " +
                    "before being sent to the server (${selfCheck.exceptionOrNull()?.let { "${it::class.simpleName}: ${it.message}" } ?: "content mismatch"})",
            )
        }
    }

    /** Same diagnostic safety gate as [verifyReencryptedPassphraseOrThrow], for the re-encrypted Name field. */
    private fun verifyReencryptedNameOrThrow(expectedName: String, armoredName: String, newParentKey: PrivateKeyHandle) {
        val selfCheck = runCatching {
            crypto.decryptArmoredAndVerify(armoredName, listOf(newParentKey), emptyList()).data.toString(Charsets.UTF_8)
        }
        val decrypted = selfCheck.getOrNull()
        if (selfCheck.isFailure || decrypted != expectedName) {
            logger.error(
                "Self-check failed for \"$expectedName\"'s re-encrypted Name before sending - refusing to proceed.\n" +
                    "Got back: $decrypted\n" +
                    "Freshly re-encrypted armored name:\n$armoredName",
                selfCheck.exceptionOrNull(),
            )
            throw ProtonDriveError(
                "Refusing to write \"$expectedName\": the freshly re-encrypted name failed to verify locally " +
                    "before being sent to the server (${selfCheck.exceptionOrNull()?.let { "${it::class.simpleName}: ${it.message}" } ?: "content mismatch"})",
            )
        }
    }

    /** Ports driveCrypto.ts's generateLookupHash(): HMAC-SHA256(parentHashKey, name), hex-encoded. */
    private fun lookupHash(name: String, parentHashKey: ByteArray): String {
        val digest = hmacSha256(parentHashKey, name.toByteArray(Charsets.UTF_8))
        return digest.toHexString()
    }
}
