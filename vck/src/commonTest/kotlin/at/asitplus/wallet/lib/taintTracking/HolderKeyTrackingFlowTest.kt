package at.asitplus.wallet.lib.taintTracking

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.CreatePresentationResult
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemoryIssuerCredentialStore
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.PresentationResponseParameters
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.StatusListAgent
import at.asitplus.wallet.lib.agent.Validator
import at.asitplus.wallet.lib.agent.ValidatorSdJwt
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.github.aakira.napier.Napier
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.serialization.json.jsonPrimitive

val HolderKeyTrackingFlowTest by testSuite {
    withFixtureGenerator {
        object {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val holderCredentialStore = InMemorySubjectCredentialStore()
            val issuer = IssuerAgent(
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://pid-issuer.at".toUri(),
                randomSource = RandomSource.Default
            )
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val validator = ValidatorSdJwt(
                validator = Validator(tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer))
            )

//            val log = KeyTouchLog()
//            val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
//            val traced: KeyMaterial = TrackingKeyMaterial(holderKeyMaterial, log)

            val keyMaterialStorage: IssuerHsmStorage = IssuerHsmStorage()
            val keyId = keyMaterialStorage.create("key-1")

            val holder = HolderAgent(
//                traced,
                EphemeralKeyWithSelfSignedCert(),
                keyStorage = keyMaterialStorage,
                subjectCredentialStore = holderCredentialStore,
                validatorSdJwt = validator,
            )
//                .also {
//                runBlocking {
//                    Napier.v("Issue Credential...", tag = "Issuer")
//                    it.storeCredential(
//                        issuer.issueCredential(
//                            DummyCredentialDataProvider.getCredential(
//                                traced.publicKey,
//                                ConstantIndex.AtomicAttribute2023,
//                                SD_JWT,
//                            ).getOrThrow()
//                        ).getOrThrow().toStoreCredentialInput()
//                    ).getOrThrow()
//                    log.touches.forEach { touch -> print("Touched key material: ${touch.toString()}\n") }
//                }
//            }

            val verifierId = "urn:${uuid4()}"
            val verifier = VerifierAgent(
                identifier = verifierId,
                validatorSdJwt = validator,
            )
            val challenge = uuid4().toString()
        }
    } - {
        "simple verification flow with stored issued credential" {

            Napier.i("Issue Credential...", tag = "Issuer")
            val credential = DummyCredentialDataProvider.getCredential(
                it.keyMaterialStorage.get(it.keyId)!!.publicKey,
                ConstantIndex.AtomicAttribute2023,
                SD_JWT,
            ).getOrThrow()

            val issuedCredential = it.issuer.issueCredential(credential)
                .getOrThrow().toStoreCredentialInput()
//            it.log.touches.forEach { touch -> print("Touched key material: ${touch.toString()}\n") }
            it.holder.storeCredential(issuedCredential).getOrThrow()
            it.keyMaterialStorage.logTouches("key-1")
                .also { keyMaterial -> (keyMaterial as TrackingKeyMaterial).clearLog() }


            Napier.i("Creating + Sending VP...", tag = "Holder")
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.keyMaterialStorage.logTouches("key-1")
                .also { keyMaterial -> (keyMaterial as TrackingKeyMaterial).clearLog() }

            Napier.i("Verify Presentation...", tag = "Verifier")
            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    reconstructedJsonObject[CLAIM_GIVEN_NAME]?.jsonPrimitive?.content shouldBe "Susanne"
                    reconstructedJsonObject[CLAIM_DATE_OF_BIRTH]?.jsonPrimitive?.content shouldBe "1990-01-01"
                    freshnessSummary.tokenStatusValidationResult
                        .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                }

//            it.log.touches.forEach { touch -> print("Touched key material: ${touch.toString()}\n") }
            it.keyMaterialStorage.logTouches("key-1")
                .also { keyMaterial -> (keyMaterial as TrackingKeyMaterial).clearLog() }
        }
    }
}

private fun buildPresentationDefinition(vararg attributeName: String) = PresentationExchangePresentation(
    CredentialPresentationRequest.PresentationExchangeRequest
        .forAttributeNames(*attributeName.map { "$['$it']" }.toTypedArray())
)