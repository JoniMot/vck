package at.asitplus.wallet.lib.cp

import at.asitplus.catching
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.iso.sha256
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.typed
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.TestCertificateAuthority
import at.asitplus.wallet.lib.agent.Validator
import at.asitplus.wallet.lib.agent.ValidatorSdJwt
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toDigest
import at.asitplus.wallet.lib.agent.toEncryptionJsonWebKey
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolver
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.sdHashInput
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock
import kotlin.time.Instant


val CrossSignedBinding by matrixSuite {

    fixture {
        runBlocking {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val issuer = IssuerAgent(
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            // HAIP requires the status list token to be signed by a certificate that is not self-signed
            val statusListCa = TestCertificateAuthority()
            val caSignedStatusListIssuer = StatusListAgent(
                keyMaterial = statusListCa.issue("Test Status List Issuer"),
                issuerCredentialStore = issuerCredentialStore,
            )

            val validator = ValidatorSdJwt(
                validator = Validator(tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer))
            )

            val wscd = SimulatedWscd()

            val holder1KeyMaterial = wscd.pidHolderKey
            val holder2KeyMaterial = wscd.eaaHolderKey

            val holderCredentialStore = InMemorySubjectCredentialStore()
            val holderCredentialStore2 = InMemorySubjectCredentialStore()

            val holder1 = HolderAgent(
                holder1KeyMaterial,
                holderCredentialStore,
                validatorSdJwt = validator,
            ).also {
                it.storeCredential(
                    issuer.issueCredential(
                        DummyCredentialDataProvider.getCredential(
                            holder1KeyMaterial.publicKey,
                            ConstantIndex.AtomicAttribute2023,
                            SD_JWT,
                        ).getOrThrow().shouldBeInstanceOf<CredentialToBeIssued.VcSd>()
                            .copy(sdAlgorithm = Digest.SHA256)
                    ).getOrThrow().toStoreCredentialInput()
                ).getOrThrow()
            }

            val holder2 = HolderAgent(
                holder2KeyMaterial,
                holderCredentialStore2,
                validatorSdJwt = validator,
            ).also {
                it.storeCredential(
                    issuer.issueCredential(
                        DummyCredentialDataProvider.getCredential(
                            holder2KeyMaterial.publicKey,
                            ConstantIndex.AtomicAttribute2023,
                            SD_JWT,
                        ).getOrThrow().shouldBeInstanceOf<CredentialToBeIssued.VcSd>()
                            .copy(sdAlgorithm = Digest.SHA256)
                    ).getOrThrow().toStoreCredentialInput()
                ).getOrThrow()
            }
            object {
                val holder1 = holder1
                val holder2 = holder2
                val wscd = wscd
                val holderCredentialStore = holderCredentialStore
                val holderCredentialStore2 = holderCredentialStore2
                val statusListIssuer = statusListIssuer
                val statusListCa = statusListCa
                val caSignedStatusListIssuer = caSignedStatusListIssuer
                val verifierId = "urn:${uuid4()}"
                val verifier = NonceChallengeVerifier(
                    verifierId = verifierId,
                    verifier = VerifierAgent(
                        identifier = verifierId,
                        validatorSdJwt = validator,
                    ),
                )
            }
        }
    } - {

        "cross-signed binding: both KB-JWTs carry common digest over holder keys and sd hashes" {
            val request = it.verifier.createPresentationRequest()

            val entry1 = it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>().first()
            val entry2 = it.holderCredentialStore2.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>().first()

            val disclosures1 = entry1.disclosures.filter { it.value!!.claimName == CLAIM_GIVEN_NAME }.keys
            val disclosures2 = entry2.disclosures.filter { it.value!!.claimName == CLAIM_DATE_OF_BIRTH }.keys

            val digest1 = entry1.sdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
            val digest2 = entry2.sdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256


            val sdHash1 = digest1.digest(SdJwtSigned.sdHashInput(entry1, disclosures1).encodeToByteArray())
            val sdHash2 = digest2.digest(SdJwtSigned.sdHashInput(entry2, disclosures2).encodeToByteArray())


            val pairs = listOf(
                Pair(it.wscd.pidHolderKey.jsonWebKey, sdHash1),
                Pair(it.wscd.eaaHolderKey.jsonWebKey, sdHash2)
            )

//            TODO something like this if need to check the sdAlg
//            val sdAlg = if vp1.sdJwt.jws.getPayload<VerifiableCredentialSdJwt>().getOrThrow().selectiveDisclosureAlgorithm!! == "sha-256"

            val crossBinding =
                crossBindingDigest(pairs, CrossBindingVariant.KEYS_AND_SD_HASH, digest1)

            val vp1 = createSdJwtPresentation(
                SignJwt(it.wscd.pidHolderKey, JwsHeaderNone()),
                request.audience,
                request.nonce,
                entry1,
                CLAIM_GIVEN_NAME,
                crossBinding = crossBinding
            )
            val vp2 = createSdJwtPresentation(
                SignJwt(it.wscd.eaaHolderKey, JwsHeaderNone()),
                request.audience, request.nonce,
                entry2 as SubjectCredentialStore.StoreEntry.SdJwt,
                CLAIM_DATE_OF_BIRTH,
                crossBinding = crossBinding
            )

            val combinedPresentation = CombinedPresentation(listOf(vp1, vp2))

            val session = it.verifier.consumeChallenge(request.nonce)

            val result1 = session.verifyPresentationSdJwt(vp1.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    reconstructedJsonObject[CLAIM_GIVEN_NAME]?.jsonPrimitive?.content shouldBe "Susanne"
                }

            val result2 = session.verifyPresentationSdJwt(vp2.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    reconstructedJsonObject[CLAIM_DATE_OF_BIRTH]?.jsonPrimitive?.content shouldBe "1990-01-01"
                }

            shouldNotThrowAny {
                verifyCrossSignedBinding(
                    listOf(result1, result2),
                    request.nonce,
                    request.audience,
                    CrossBindingVariant.KEYS_AND_SD_HASH
                )
            }
        }
    }
}

/** Presents the stored SD-JWT to a verifier using [tokenStatusResolver], and returns the status of the token. */
private suspend fun presentAndVerifySdJwt(
    holder: Holder,
    verifierId: String,
    tokenStatusResolver: TokenStatusResolver,
): TokenStatusValidationResult {
    val verifier = NonceChallengeVerifier(
        verifierId = verifierId,
        verifier = VerifierAgent(
            identifier = verifierId,
            validatorSdJwt = ValidatorSdJwt(
                validator = Validator(tokenStatusResolver = tokenStatusResolver),
            ),
        ),
    )
    val presentationParameters = holder.createDefaultPresentation(
        request = verifier.createPresentationRequest(),
        credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
            buildDCQLQuery(
                DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
            ),
        )
    ).getOrThrow() as PresentationResponseParameters.DCQLParameters
    val vp = presentationParameters.verifiablePresentations.values.first().first()
        .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

    return verifier.verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        .freshnessSummary.tokenStatusValidationResult
}

private fun buildDCQLQuery(vararg claimsQueries: DCQLJsonClaimsQuery) = DCQLQuery(
    credentials = DCQLCredentialQueryList(
        DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(uuid4().toString()),
            format = CredentialFormatEnum.DC_SD_JWT,
            claims = DCQLClaimsQueryList(
                claimsQueries.toList().toNonEmptyList(),
            ),
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf(ConstantIndex.AtomicAttribute2023.sdJwtType)
            )
        )
    )
)

private suspend fun createSdJwtPresentation(
    signKeyBindingJws: SignJwtFun<CrossBoundKeyBindingJws>,
    audienceId: String,
    challenge: String,
    validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
    claimName: String,
    crossBinding: ByteArray?
): CreatePresentationResult.SdJwt {
    val filteredDisclosures = validSdJwtCredential.disclosures
        .filter { it.value!!.claimName == claimName }.keys
    val issuerJwtPlusDisclosures = SdJwtSigned.sdHashInput(validSdJwtCredential, filteredDisclosures)
    val keyBinding =
        createCrossBoundKeyBindingJws(signKeyBindingJws, audienceId, challenge, issuerJwtPlusDisclosures, crossBinding)
    val sdJwtSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
    val jwsFromIssuer = catching { JwsCompact(sdJwtSerialized) }.getOrElse {
        throw PresentationException(it)
    }
    val sdJwt = SdJwtSigned.presented(jwsFromIssuer, filteredDisclosures, keyBinding = keyBinding)
    return CreatePresentationResult.SdJwt(sdJwt.serialize(), sdJwt)
}

private suspend fun createCrossBoundKeyBindingJws(
    signKeyBindingJws: SignJwtFun<CrossBoundKeyBindingJws>,
    audienceId: String,
    challenge: String,
    issuerJwtPlusDisclosures: String,
    crossBinding: ByteArray?
): JwsCompactTyped<KeyBindingJws> = signKeyBindingJws(
    JwsContentTypeConstants.KB_JWT,
    CrossBoundKeyBindingJws(
        issuedAt = Clock.System.now(),
        audience = audienceId,
        challenge = challenge,
        sdHash = issuerJwtPlusDisclosures.encodeToByteArray().sha256(),
        crossBinding = crossBinding
    ),
    CrossBoundKeyBindingJws.serializer(),
).getOrElse {
    throw PresentationException(it)
}.jws.typed()

@Serializable
data class CrossBoundKeyBindingJws(
    // KB-JWT payload + cross_binding
    @SerialName("iat") @Serializable(InstantLongSerializer::class) val issuedAt: Instant,
    @SerialName("aud") val audience: String,
    @SerialName("nonce") val challenge: String,
    @SerialName("sd_hash") @Serializable(ByteArrayBase64UrlSerializer::class) val sdHash: ByteArray,
    @SerialName("cross_binding") @Serializable(ByteArrayBase64UrlSerializer::class) val crossBinding: ByteArray? = null,
)

enum class CrossBindingVariant { KEYS, KEYS_AND_SD_HASH }

// Extend when not wanting to use Sha-256 but _sd_alg from first attestation
private fun JsonWebKey.wscdFingerprint(): String = jwkThumbprint

private fun crossBindingDigest(
    entries: List<Pair<JsonWebKey, ByteArray>>, // (holder pk, sd_hash), in CP order
    variant: CrossBindingVariant = CrossBindingVariant.KEYS,
    digest: Digest = Digest.SHA256, // _sd_alg of first attestation, default SHA-256
): ByteArray {
    if (variant == CrossBindingVariant.KEYS) {
        return digest.digest(
            entries.fold(byteArrayOf()) { acc, (key, _) -> acc + key.wscdFingerprint().encodeToByteArray() }
        )
    } else {
        return digest.digest(
            entries.fold(byteArrayOf()) { acc, (key, sdHash) ->
                acc + (key.wscdFingerprint().encodeToByteArray() + sdHash)
            }
        )
    }
}

private fun verifyCrossSignedBinding(
    presentations: List<Verifier.VerifyPresentationResult.SuccessSdJwt>,
    expectedNonce: String,
    expectedAudience: String,
    variant: CrossBindingVariant,
) {
    val holderKeySdHashPairs = presentations.map {
        Pair(
            it.verifiableCredentialSdJwt.confirmationClaim!!.jsonWebKey!!,
            it.sdJwtSigned.keyBindingJws!!.payload.sdHash
        )
    }
    val digest = presentations.first().verifiableCredentialSdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
    val expected = crossBindingDigest(holderKeySdHashPairs, variant, digest)


    presentations.forEach {
        val kb = it.sdJwtSigned.keyBindingJws!!.jws.getPayload<CrossBoundKeyBindingJws>().getOrThrow()

        kb.challenge shouldBe expectedNonce
        kb.audience shouldBe expectedAudience
        kb.crossBinding.shouldNotBeNull().contentEquals(expected).shouldBeTrue()
    }
}