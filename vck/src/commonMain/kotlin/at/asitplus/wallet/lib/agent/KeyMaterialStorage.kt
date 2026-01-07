package at.asitplus.wallet.lib.agent

interface KeyMaterialStorage {
    fun create(keyId: String?): String
    fun store(keyId: String, keyMaterial: KeyMaterial)
    fun get(keyId: String): KeyMaterial?
    fun clear()
    fun clearLog(keyId: String)
    fun logTouches(keyId: String, tag: String? = null): KeyMaterial?
}