package at.asitplus.wallet.lib.taintTracking

data class KeyTouch(val what: String, val by: String)

class KeyTouchLog {
    private val _touches = mutableListOf<KeyTouch>()
    val touches: List<KeyTouch> get() = _touches
    fun add(what: String) { _touches += KeyTouch(what, currentCallerClass()) }
    fun clear() { _touches.clear() }
}

private fun currentCallerClass(): String = callerClass()


