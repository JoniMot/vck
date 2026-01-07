import at.asitplus.testballoon.FreeSpec
import de.infix.testBalloon.framework.core.TestInvocation
import de.infix.testBalloon.framework.core.TestSession
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testScope
import io.github.aakira.napier.Antilog
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.LogLevel
import io.github.aakira.napier.Napier
import kotlin.time.Duration.Companion.minutes

expect val testNameLengths: Pair<Int, Int>

class TestConfig : TestSession(
    testConfig = DefaultConfiguration.invocation(TestInvocation.SEQUENTIAL)
        .testScope(isEnabled = true, timeout = 20.minutes)
) {
    init {
        Napier.takeLogarithm()
        Napier.base(InfoOnlyAntilog())
//        Napier.base(DebugAntilog())

        FreeSpec.defaultMaxLength = testNameLengths.first //work around Android test name length limit
        FreeSpec.defaultDisplayNameMaxLength = testNameLengths.second //work around Android test name length limit
    }
}

class InfoOnlyAntilog : Antilog() {
    override fun performLog(
        priority: LogLevel,
        tag: String?,
        throwable: Throwable?,
        message: String?
    ) {
        if (priority != LogLevel.INFO) return

        println("[INFO] ${tag ?: ""} - $message")
        throwable?.printStackTrace()
    }
}
