@file:OptIn(ExperimentalStdlibApi::class)

package dev.carlsen.protondrive.sdk.nodes

import dev.carlsen.protondrive.sdk.SdkEvents
import dev.carlsen.protondrive.sdk.account.ResolvedAddress
import dev.carlsen.protondrive.sdk.apiService.APICodeError
import dev.carlsen.protondrive.sdk.apiService.DriveAPIService
import dev.carlsen.protondrive.sdk.apiService.ErrorCode
import dev.carlsen.protondrive.sdk.crypto.OpenPGPCrypto
import dev.carlsen.protondrive.sdk.crypto.PGPainlessOpenPGPCrypto
import dev.carlsen.protondrive.sdk.crypto.hmacSha256
import dev.carlsen.protondrive.sdk.crypto.toPublicKeyHandle
import dev.carlsen.protondrive.sdk.errors.NodeWithSameNameExistsValidationError
import dev.carlsen.protondrive.sdk.testing.FakeHttpClient
import dev.carlsen.protondrive.sdk.testing.FakeJsonResponse
import dev.carlsen.protondrive.sdk.testing.FakeTelemetry
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Covers the createFolder/listChildren collision-detection behavior added to handle a real
 * production symptom: a name-hash collision against an orphaned, undecryptable sibling link
 * (debris from an earlier interrupted operation) makes the server return a confusing
 * crypto-verification error on an unmapped code instead of the well-known ALREADY_EXISTS - see
 * the "orphaned debris" comment on listChildren and the try/catch in createFolder.
 */
class DriveClientTest {

    private val crypto: OpenPGPCrypto = PGPainlessOpenPGPCrypto()
    private val addressEmail = "user@example.com"
    private val volumeId = "volume1"
    private val rootLinkId = "root-link"

    private fun newClient(httpClient: FakeHttpClient, address: ResolvedAddress): DriveClient {
        val telemetry = FakeTelemetry()
        val apiService = DriveAPIService(
            telemetry = telemetry,
            sdkEvents = SdkEvents(telemetry),
            httpClient = httpClient,
            baseUrl = "https://api.example",
            language = "en",
        )
        return DriveClient(apiService, crypto, listOf(address), telemetry)
    }

    /** Builds a my-files bootstrap fixture: an address key, a share key, and the root folder's own key/hashKey - everything [DriveClient.getMyFilesRoot] needs to decrypt successfully. */
    private fun buildRootBootstrap(): Pair<ResolvedAddress, FakeJsonResponse> {
        val addressKey = crypto.generateKey(crypto.generatePassphrase())
        val address = ResolvedAddress(addressId = "addr1", email = addressEmail, keys = listOf(addressKey.privateKey))

        val sharePassphrase = crypto.generatePassphrase()
        val shareKey = crypto.generateKey(sharePassphrase)
        val shareEncryptedPassphrase = crypto.encryptAndSignDetachedArmored(
            sharePassphrase.toByteArray(Charsets.UTF_8),
            listOf(addressKey.privateKey.toPublicKeyHandle()),
            addressKey.privateKey,
        )

        val rootPassphrase = crypto.generatePassphrase()
        val rootKey = crypto.generateKey(rootPassphrase)
        val rootEncryptedPassphrase = crypto.encryptAndSignDetachedArmored(
            rootPassphrase.toByteArray(Charsets.UTF_8),
            listOf(shareKey.privateKey.toPublicKeyHandle()),
            addressKey.privateKey,
        )
        val rootArmoredName = crypto.encryptAndSignArmored(
            "root".toByteArray(Charsets.UTF_8),
            listOf(shareKey.privateKey.toPublicKeyHandle()),
            addressKey.privateKey,
        )
        val rootHashKeyMaterial = crypto.generatePassphrase().toByteArray(Charsets.UTF_8)
        val rootArmoredHashKey = crypto.encryptAndSignArmored(
            rootHashKeyMaterial,
            listOf(rootKey.privateKey.toPublicKeyHandle()),
            rootKey.privateKey,
        )

        val bootstrapBody = PrimaryRootShareResponse(
            code = ErrorCode.OK,
            volume = VolumeDto(volumeId = volumeId),
            share = ShareDto(
                shareId = "share1",
                creatorEmail = addressEmail,
                key = shareKey.armoredKey,
                passphrase = shareEncryptedPassphrase.armoredData,
                passphraseSignature = shareEncryptedPassphrase.armoredSignature,
                addressId = address.addressId,
            ),
            link = LinkDetails(
                link = LinkDto(
                    linkId = rootLinkId,
                    type = NodeType.FOLDER,
                    parentLinkId = null,
                    modifyTime = 0,
                    name = rootArmoredName,
                    nodeKey = rootKey.armoredKey,
                    nodePassphrase = rootEncryptedPassphrase.armoredData,
                    nodePassphraseSignature = rootEncryptedPassphrase.armoredSignature,
                    signatureEmail = addressEmail,
                ),
                folder = FolderDto(nodeHashKey = rootArmoredHashKey, xAttr = null),
            ),
        )
        val response = FakeJsonResponse(status = 200, body = Json.encodeToJsonElement(bootstrapBody))
        return address to response
    }

    private fun errorBody(code: Int, message: String) = buildJsonObject {
        put("Code", code)
        put("Error", message)
    }

    /** An undecryptable sibling link - garbage crypto fields, but a real (matching) NameHash. */
    private fun orphanLinkDetails(linkId: String, nameHash: String) = LinkDetails(
        link = LinkDto(
            linkId = linkId,
            type = NodeType.FOLDER,
            parentLinkId = rootLinkId,
            modifyTime = 0,
            name = "not a valid armored message",
            nameHash = nameHash,
            nodeKey = "not a valid armored key",
            nodePassphrase = "not a valid armored message",
            nodePassphraseSignature = "not a valid armored signature",
            signatureEmail = addressEmail,
        ),
        folder = FolderDto(nodeHashKey = null, xAttr = null),
    )

    @Test
    fun `listChildren surfaces an undecryptable sibling with its plaintext NameHash`() = runTest {
        val (address, bootstrapResponse) = buildRootBootstrap()
        val httpClient = FakeHttpClient()
        httpClient.enqueueResponse(bootstrapResponse)
        val client = newClient(httpClient, address)
        val root = client.getMyFilesRoot()

        httpClient.enqueueResponse(
            FakeJsonResponse(
                status = 200,
                body = Json.encodeToJsonElement(ListChildrenResponse(code = ErrorCode.OK, linkIds = listOf("orphan-1"), more = false)),
            ),
        )
        httpClient.enqueueResponse(
            FakeJsonResponse(
                status = 200,
                body = Json.encodeToJsonElement(
                    LoadLinksResponse(code = ErrorCode.OK, links = listOf(orphanLinkDetails("orphan-1", "orphan-hash"))),
                ),
            ),
        )

        val children = client.listChildren(root)

        assertEquals(1, children.size)
        assertTrue(children.single().name.startsWith("<undecryptable:"))
        assertEquals("orphan-hash", children.single().hash)
    }

    @Test
    fun `createFolder detects a hash collision with an undecryptable sibling and throws NodeWithSameNameExistsValidationError`() = runTest {
        val (address, bootstrapResponse) = buildRootBootstrap()
        val httpClient = FakeHttpClient()
        httpClient.enqueueResponse(bootstrapResponse)
        val client = newClient(httpClient, address)
        val root = client.getMyFilesRoot()

        val folderName = "New Folder"
        val expectedHash = hmacSha256(root.hashKey!!, folderName.toByteArray(Charsets.UTF_8)).toHexString()

        // The create attempt itself fails with the confusing, unmapped error the server
        // actually returns for this collision (see production symptom in the linked issue).
        httpClient.enqueueResponse(
            FakeJsonResponse(
                status = 200,
                body = errorBody(999999, "Could not verify the nodeKey was used for encrypting xAttr, nodeHashKey"),
            ),
        )
        httpClient.enqueueResponse(
            FakeJsonResponse(
                status = 200,
                body = Json.encodeToJsonElement(ListChildrenResponse(code = ErrorCode.OK, linkIds = listOf("orphan-1"), more = false)),
            ),
        )
        httpClient.enqueueResponse(
            FakeJsonResponse(
                status = 200,
                body = Json.encodeToJsonElement(
                    LoadLinksResponse(code = ErrorCode.OK, links = listOf(orphanLinkDetails("orphan-1", expectedHash))),
                ),
            ),
        )

        val error = assertFailsWith<NodeWithSameNameExistsValidationError> {
            client.createFolder(root, folderName)
        }
        assertEquals("orphan-1", error.existingNodeUid)
    }

    @Test
    fun `createFolder rethrows the original error when no collision is found`() = runTest {
        val (address, bootstrapResponse) = buildRootBootstrap()
        val httpClient = FakeHttpClient()
        httpClient.enqueueResponse(bootstrapResponse)
        val client = newClient(httpClient, address)
        val root = client.getMyFilesRoot()

        httpClient.enqueueResponse(
            FakeJsonResponse(status = 200, body = errorBody(999999, "some other genuine failure")),
        )
        // No siblings at all - listChildren returns early without a loadLinks call.
        httpClient.enqueueResponse(
            FakeJsonResponse(
                status = 200,
                body = Json.encodeToJsonElement(ListChildrenResponse(code = ErrorCode.OK, linkIds = emptyList(), more = false)),
            ),
        )

        val error = assertFailsWith<APICodeError> {
            client.createFolder(root, "New Folder")
        }
        assertEquals("some other genuine failure", error.message)
    }
}
