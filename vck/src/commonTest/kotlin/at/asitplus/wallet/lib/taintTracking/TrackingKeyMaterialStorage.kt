package at.asitplus.wallet.lib.taintTracking

import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.KeyMaterialStorage
import io.github.aakira.napier.Napier

/**
 * Simulates a storage for TrackingKeyMaterial instances, logging access operations.
 * Can be seen as external storage, e.g. HSM or Smartcard.
 */
abstract class TrackingKeyMaterialStorage(
    private val storage: MutableMap<String, TrackingKeyMaterial> = mutableMapOf(),
    private val component: String
) : KeyMaterialStorage {

    override fun create(keyId: String?): String {
        val id = keyId ?: "key-${storage.size + 1}"
        val keyMaterial = EphemeralKeyWithSelfSignedCert()
        val log = KeyTouchLog()
        store(id, TrackingKeyMaterial(keyMaterial, log))
        return id
    }

    override fun store(keyId: String, keyMaterial: KeyMaterial) {
        storage[keyId] = keyMaterial as TrackingKeyMaterial
    }

    override fun get(keyId: String): TrackingKeyMaterial? {
        return storage[keyId]
    }

    override fun clear() {
        storage.clear()
    }

    override fun clearLog(keyId: String) {
        val keyMaterial = storage[keyId]
        if (keyMaterial != null) {
            keyMaterial.clearLog()
        } else {
            Napier.i(message = "No key material found for keyId: $keyId")
        }
    }

    override fun logTouches(keyId: String, tag: String?): KeyMaterial?{
        val keyMaterial = storage[keyId]
        if (keyMaterial != null) {
            keyMaterial.logTouches(tag ?: ("Contact to $component"))
        } else {
            Napier.i(message = "No key material found for keyId: $keyId")
        }

        return keyMaterial
    }
}

/**
 * HSM provided by issuer
 */
class IssuerHsmStorage(
    storage: MutableMap<String, TrackingKeyMaterial> = mutableMapOf(),
) : TrackingKeyMaterialStorage(
    storage = storage,
    component = "Issuer HSM"
)

/**
 * HSM provided by third party
 */
class ThirdPartyHsmStorage(
    storage: MutableMap<String, TrackingKeyMaterial> = mutableMapOf(),
) : TrackingKeyMaterialStorage(
    storage = storage,
    component = "ThirdParty HSM"
)

/**
 * Smartcard provided by holder
 */
class HolderSmartcardStorage(
    storage: MutableMap<String, TrackingKeyMaterial> = mutableMapOf(),
) : TrackingKeyMaterialStorage(
    storage = storage,
    component = "Holder Smartcard"
)