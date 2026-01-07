package at.asitplus.wallet.lib.taintTracking

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.supreme.sign.SignatureInput
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.wallet.lib.agent.KeyMaterial
import io.github.aakira.napier.Napier

class TrackingKeyMaterial(
    private val keyMaterial: KeyMaterial,
    private val log: KeyTouchLog
) : KeyMaterial {

    override val identifier: String get() = keyMaterial.identifier
    override val signatureAlgorithm: SignatureAlgorithm get() = keyMaterial.signatureAlgorithm

    override val publicKey: CryptoPublicKey
        get() = keyMaterial.publicKey.also { log.add("publicKey") }

    override val jsonWebKey: JsonWebKey
        get() = keyMaterial.jsonWebKey.also { log.add("jsonWebKey") }

    override suspend fun getCertificate(): X509Certificate? =
        keyMaterial.getCertificate().also { log.add("getCertificate") }

    override fun getUnderLyingSigner(): Signer =
        keyMaterial.getUnderLyingSigner().also { log.add("getUnderLyingSigner") }

    override suspend fun sign(data: SignatureInput): SignatureResult<*> =
        keyMaterial.sign(data).also { log.add("sign(SignatureInput)") }

    @OptIn(SecretExposure::class)
    override fun exportPrivateKey(): KmmResult<CryptoPrivateKey.WithPublicKey<*>> =
        keyMaterial.exportPrivateKey().also { log.add("exportPrivateKey") }

    fun logTouches(component: String) {
        for (touch in log.touches) {
            Napier.i (message = ("KeyTouch - what: ${touch.what}, by: ${touch.by}"), tag = component )
        }
    }

    fun clearLog() {
        log.clear()
    }
}
