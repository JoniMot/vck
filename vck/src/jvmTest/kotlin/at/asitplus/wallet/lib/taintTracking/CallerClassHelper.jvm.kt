package at.asitplus.wallet.lib.taintTracking

actual fun callerClass(): String =
    Throwable().stackTrace
        .firstOrNull { ste ->
            val c = ste.className
            !c.startsWith("java.") &&
                    !c.startsWith("kotlin.") &&
                    !c.startsWith("kotlinx.") &&
                    !c.startsWith("io.kotest.") &&
                    !c.startsWith("de.infix.") &&
                    !c.contains("taintTracking.") &&
                    !c.contains("sign.")
        }
        ?.toString() ?: "UNKNOWN"