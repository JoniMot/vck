package at.asitplus.wallet.lib.cp

import at.asitplus.KmmResult
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
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.FixedTimePeriodProvider
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
import at.asitplus.wallet.lib.agent.toEncryptionJsonWebKey
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.ifFalse
import at.asitplus.wallet.lib.extensions.sdHashInput
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import at.asitplus.wallet.lib.jws.VerifyStatusListTokenHAIP
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock


val WscdSignedBinding by matrixSuite {

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

        "wscd binding: combined presentation with trusted statement verifies" {
            val request = it.verifier.createPresentationRequest()
            val presentationParameters = it.holder1.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        ),
                    )
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp1 = presentationParameters.verifiablePresentations.values.flatten().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val presentation2Parameters = it.holder2.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_DATE_OF_BIRTH),
                        ),
                    )
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp2 = presentation2Parameters.verifiablePresentations.values.flatten().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val signedBindingStatement = it.wscd.signBindingStatement(
                listOf(it.wscd.pidHolderKey.jsonWebKey, it.wscd.eaaHolderKey.jsonWebKey),
                request.nonce,
                request.audience
            )

            val combinedPresentation = CombinedPresentation(listOf(vp1, vp2), signedBindingStatement)

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
                verifyWscdBinding(
                    signedBindingStatement,
                    listOf(result1, result2),
                    setOf(it.wscd.wscdKey.publicKey),
                    request.nonce,
                    request.audience
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

suspend fun createFreshSdJwtKeyBinding(challenge: String, verifierId: String): String {
    val holderKeyMaterial = EphemeralKeyWithoutCert()
    val holder = HolderAgent(holderKeyMaterial)
    val issuer = IssuerAgent(
        identifier = "https://issuer.example.com/".toUri(),
        randomSource = RandomSource.Default
    )
    DummyCredentialDataProvider.issueAndStoreSdJwt(holder, holderKeyMaterial, issuer)

    val presentationResult = holder.createDefaultPresentation(
        request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
        credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
            buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                )
            )
        )
    ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()
    return (presentationResult.verifiablePresentations.values.first()
        .first() as CreatePresentationResult.SdJwt).serialized
}

private suspend fun createSdJwtPresentation(
    signKeyBindingJws: SignJwtFun<KeyBindingJws>,
    audienceId: String,
    challenge: String,
    validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
    claimName: String,
): CreatePresentationResult.SdJwt {
    val filteredDisclosures = validSdJwtCredential.disclosures
        .filter { it.value!!.claimName == claimName }.keys
    val issuerJwtPlusDisclosures = SdJwtSigned.sdHashInput(validSdJwtCredential, filteredDisclosures)
    val keyBinding = createKeyBindingJws(signKeyBindingJws, audienceId, challenge, issuerJwtPlusDisclosures)
    val sdJwtSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
    val jwsFromIssuer = catching { JwsCompact(sdJwtSerialized) }.getOrElse {
        throw PresentationException(it)
    }
    val sdJwt = SdJwtSigned.presented(jwsFromIssuer, filteredDisclosures, keyBinding)
    return CreatePresentationResult.SdJwt(sdJwt.serialize(), sdJwt)
}

private suspend fun createKeyBindingJws(
    signKeyBindingJws: SignJwtFun<KeyBindingJws>,
    audienceId: String,
    challenge: String,
    issuerJwtPlusDisclosures: String,
): JwsCompactTyped<KeyBindingJws> = signKeyBindingJws(
    JwsContentTypeConstants.KB_JWT,
    KeyBindingJws(
        issuedAt = Clock.System.now(),
        audience = audienceId,
        challenge = challenge,
        sdHash = issuerJwtPlusDisclosures.encodeToByteArray().sha256(),
    ),
    KeyBindingJws.serializer(),
).getOrElse {
    throw PresentationException(it)
}

data class SimulatedWscd(
    val pidHolderKey: KeyMaterial = EphemeralKeyWithoutCert(customKeyId = "pid_key"),
    val eaaHolderKey: KeyMaterial = EphemeralKeyWithoutCert(customKeyId = "eaa_key"),
//    val holderKeys: List<JsonWebKey> = emptyList(),
    val wscdKey: KeyMaterial = EphemeralKeyWithoutCert()
) {
    suspend fun signBindingStatement(
        holderKeys: List<JsonWebKey>,
        nonce: String,
        audience: String
    ): JwsCompactTyped<WscdBindingStatement> {
        checkPossessionOfHolderKey(holderKeys)
        val payload = WscdBindingStatement(holderKeys.map { it.wscdFingerprint() }, nonce, audience)
        return SignJwt<WscdBindingStatement>(wscdKey, JwsHeaderNone())(
            type = "wscd-binding+jwt",
            payload = payload,
            serializer = WscdBindingStatement.serializer()
        ).getOrThrow()
    }

    private fun checkPossessionOfHolderKey(holderKeys: List<JsonWebKey>) {
        holderKeys.any {
            mutableListOf(
                pidHolderKey.toEncryptionJsonWebKey().wscdFingerprint(),
                eaaHolderKey.toEncryptionJsonWebKey().wscdFingerprint()
            ).contains(it.wscdFingerprint()).shouldBeTrue()
        }
    }
}

// Extend when not wanting to use Sha-256 but _sd_alg from first attestation
private fun JsonWebKey.wscdFingerprint(): String = jwkThumbprint

@Serializable
data class WscdBindingStatement(
    @SerialName("keys")
    val keys: List<String>,
    @SerialName("nonce")
    val nonce: String,
    @SerialName("aud")
    val audience: String,
) {}

data class CombinedPresentation(
    val attestations: List<CreatePresentationResult>,
    val bindingStatement: JwsCompactTyped<WscdBindingStatement>
)

private suspend fun verifyWscdBinding(
    statement: JwsCompactTyped<WscdBindingStatement>,
    presentations: List<Verifier.VerifyPresentationResult.SuccessSdJwt>,
    trustedWscdKeys: Set<CryptoPublicKey>,
    expectedNonce: String,
    expectedAudience: String
) {
    trustedWscdKeys.any { VerifyJwsSignature()(statement.jws, it).isSuccess }
    val keyFingerprints =
        presentations.map { it.verifiableCredentialSdJwt.confirmationClaim!!.jsonWebKey!!.wscdFingerprint() }
    statement.payload.keys.forEach { keyFingerprints.contains(it).shouldBeTrue() }

    expectedAudience shouldBe statement.payload.audience
    expectedNonce shouldBe statement.payload.nonce
}