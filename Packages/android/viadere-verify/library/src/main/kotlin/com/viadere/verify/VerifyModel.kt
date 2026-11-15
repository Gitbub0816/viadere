package com.viadere.verify

import java.net.URI

/*
 * The platform-neutral part of the Android "Verify with Viadere" button: the session link, the hand-off rule and the QR-first panel as a state
 * machine. Pure Kotlin (no Android types), unit-tested on the JVM. The same table as the web component and the iOS SDK (docs/VERIFY-BUTTON.md).
 *
 * The button runs in your app and never holds an API key: your app gets the session's link from YOUR server, which created it
 * (`POST /v1/business/verification-sessions`), and your server learns the outcome from Viadere's signed result, never from the app.
 */

/** A verification-session link: `https://{viadere.com | viadere.cksites.dev}/v/{CODE}`, nothing else. */
class VerifySession private constructor(
    /** The exact link, used as the App Link and as the QR content. */
    val link: String,
    /** Canonical code (eight characters of the code alphabet). */
    val code: String,
    /** When the code stops working (epoch milliseconds), if your server passed it on. */
    val expiresAtMillis: Long?,
) {
    /** `ABCD-EFGH`, what the person types into the app. */
    val displayCode: String get() = code.substring(0, 4) + "-" + code.substring(4)

    /** `A B C D E F G H`, for TalkBack. */
    val spokenCode: String get() = code.toList().joinToString(" ")

    fun isExpired(nowMillis: Long): Boolean = expiresAtMillis?.let { it <= nowMillis } ?: false

    override fun equals(other: Any?): Boolean = other is VerifySession && other.link == link && other.expiresAtMillis == expiresAtMillis
    override fun hashCode(): Int = link.hashCode() * 31 + (expiresAtMillis?.hashCode() ?: 0)
    override fun toString(): String = "VerifySession($displayCode)"

    companion object {
        val DEFAULT_HOSTS: Set<String> = setOf("viadere.com", "viadere.cksites.dev")
        /** The code alphabet: no I, O, 0 or 1. */
        private val PATTERN = Regex("^https://([a-z0-9.-]+)/v/([A-HJ-NP-Z2-9]{8})$")

        /** `null` unless [link] is exactly a session link on one of [allowedHosts] (https, `/v/{CODE}`, no port, query or fragment). */
        fun parse(link: String, expiresAtMillis: Long? = null, allowedHosts: Set<String> = DEFAULT_HOSTS): VerifySession? {
            val match = PATTERN.matchEntire(link) ?: return null
            val host = match.groupValues[1]
            if (host !in allowedHosts) return null
            // Belt and braces: the platform parser must agree (no user info, no port, nothing after the path).
            val uri = try { URI(link) } catch (_: Exception) { return null }
            if (uri.scheme != "https" || uri.host != host || uri.port != -1 || uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null) return null
            return VerifySession(link, match.groupValues[2], expiresAtMillis)
        }
    }
}

/** The flow a button starts. Only [VERIFY] exists; a sign-in flow adds an entry and its copy here (the button and panel are generic). */
enum class VerifyFlow(val label: String, val title: String, val scanPrompt: String, val explanation: String) {
    VERIFY(
        label = "Verify with Viadere",
        title = "Verify with Viadere",
        scanPrompt = "Scan with your phone’s camera",
        explanation = "Viadere opens and shows you which verified business is asking and exactly what it would learn. Nothing is shared until you approve.",
    ),
}

enum class VerifyVariant { FILLED, IVORY, OUTLINE }

/** Heights in dp; [minimumTouchTarget] is the reserved touch area (Material and WCAG: 48 dp). */
enum class VerifySize(val heightDp: Int, val fontSp: Int) {
    SMALL(36, 13), MEDIUM(44, 15), LARGE(52, 17);

    val minimumTouchTargetDp: Int get() = 48
}

enum class VerifyDisplay { LABEL, ICON_ONLY }

/** The button's colours (0xRRGGBB), the same as `viadere-verify.css`, the iOS SDK and `Design/embeds/`. `background == null` is transparent. */
data class VerifyColors(val background: Long?, val foreground: Long, val border: Long) {
    companion object {
        fun of(variant: VerifyVariant, dark: Boolean): VerifyColors = when (variant) {
            VerifyVariant.FILLED -> if (dark) VerifyColors(0xF3F0EAL, 0x1F1E1CL, 0xF3F0EAL) else VerifyColors(0x1F1E1CL, 0xF5F2ECL, 0x1F1E1CL)
            VerifyVariant.IVORY -> VerifyColors(0xF5F2ECL, 0x1F1E1CL, 0xC9C4BBL)
            VerifyVariant.OUTLINE -> if (dark) VerifyColors(null, 0xF3F0EAL, 0xF3F0EAL) else VerifyColors(null, 0x1F1E1CL, 0x1F1E1CL)
        }
    }
}

// Hand-off -----------------------------------------------------------------------------------------------------------------------------

enum class VerifyDevice {
    /** A phone or tablet: Android can hand an App Link to the Viadere app when it is installed and verified for the link domain. */
    HANDHELD,

    /** A ChromeOS laptop or desktop-mode window: the QR-first panel (scan with your phone). */
    COMPUTER,
}

sealed interface VerifyAction {
    /** Open the link only if a verified app (not a browser) handles it: `FLAG_ACTIVITY_REQUIRE_NON_BROWSER`. */
    data class OpenInApp(val link: String) : VerifyAction
    data object ShowPanel : VerifyAction
    data object HandedOff : VerifyAction
    /** The code expired: ask your server for a new session. */
    data object Expired : VerifyAction
}

/** The owner's rule: hand off automatically when the app can take the link; otherwise the QR first, with a button for the other options. */
object VerifyHandoff {
    fun onTap(device: VerifyDevice, session: VerifySession, nowMillis: Long): VerifyAction = when {
        session.isExpired(nowMillis) -> VerifyAction.Expired
        device == VerifyDevice.HANDHELD -> VerifyAction.OpenInApp(session.link)
        else -> VerifyAction.ShowPanel
    }

    fun afterOpenInApp(opened: Boolean): VerifyAction = if (opened) VerifyAction.HandedOff else VerifyAction.ShowPanel
}

// Panel ------------------------------------------------------------------------------------------------------------------------------------

enum class VerifyOption(val title: String, val detail: String) {
    OPEN_ON_THIS_DEVICE("Open Viadere on this device", "If the Viadere app is installed here."),
    ENTER_CODE("Enter a code in the app", "Type a short code into Viadere on your phone."),

    /** Only when your server can reach this customer's phone (an existing connection: your server creates an ordinary verification request
     *  for their `subject_ref`, which Viadere pushes). The library never sends anything itself. */
    SEND_TO_PHONE("Send to my phone", "Get a Viadere notification on the phone linked to your account."),
    GET_APP("Get the Viadere app", "Then scan the code again."),
}

/** The QR-first panel as an immutable state machine; the Compose dialog renders it, tests drive it. */
data class VerifyPanelState(
    val session: VerifySession,
    val options: List<VerifyOption>,
    val screen: Screen = Screen.QR,
    val showsCode: Boolean = false,
    /** An announcement for TalkBack / the status line. */
    val status: String? = null,
) {
    enum class Screen { QR, OPTIONS }

    sealed interface Effect {
        data object None : Effect
        /** Open the session link normally (the app if it claims it, otherwise the landing page with the store link). */
        data class Open(val link: String) : Effect
        data object SendToPhone : Effect
    }

    fun chooseAnotherOption(): VerifyPanelState = copy(screen = Screen.OPTIONS)

    fun backToQr(): VerifyPanelState = copy(screen = Screen.QR, showsCode = false, status = null)

    fun select(option: VerifyOption): Pair<VerifyPanelState, Effect> {
        if (option !in options) return this to Effect.None
        return when (option) {
            VerifyOption.OPEN_ON_THIS_DEVICE, VerifyOption.GET_APP -> this to Effect.Open(session.link)
            VerifyOption.ENTER_CODE -> copy(showsCode = true, status = "Your code is ${session.spokenCode}.") to Effect.None
            VerifyOption.SEND_TO_PHONE -> copy(status = "Check your phone for a notification from Viadere.") to Effect.SendToPhone
        }
    }

    companion object {
        fun initial(session: VerifySession, sendToPhone: Boolean): VerifyPanelState =
            VerifyPanelState(session, VerifyOption.entries.filter { it != VerifyOption.SEND_TO_PHONE || sendToPhone })
    }
}

/**
 * Recognises the return to your app after the person verified: the Viadere app opens the session's `return_url` (same origin as the session,
 * checked by Viadere's server and again by the app), which your app receives as its own App Link. **It carries no result**: on return, ask your
 * server, which reads the session and verifies Viadere's signed result.
 */
object VerifyReturn {
    /** Whether [uri] is exactly the return URL your server set for the session (scheme, host and path; your server decides about the query). */
    fun isReturn(uri: String, expectedReturnUrl: String): Boolean {
        val a = try { URI(uri) } catch (_: Exception) { return false }
        val b = try { URI(expectedReturnUrl) } catch (_: Exception) { return false }
        return a.scheme == "https" && a.scheme == b.scheme && a.host != null && a.host == b.host && a.port == b.port && a.rawUserInfo == null &&
            a.rawPath == b.rawPath && a.rawFragment == null
    }
}

/** The mark's path data (absolute M L C Z, 321.71 × 146 view box): `Design/svg/viadere-mark-mono-dark.svg`. */
object VerifyMark {
    const val WIDTH = 321.71f
    const val HEIGHT = 146f
    const val DOT_X = 155.21f
    const val DOT_Y = 20.5f
    const val DOT_R = 20.5f
    const val BACK_ALPHA = 0.62f
    const val BACK =
        "M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z"
    val FRONT = listOf(
        "M0 46C31.34 46 52.61 53.08 58.62 61.38L88.74 102.99C101.18 120.16 102.65 139.14 118.23 127.81L116.14 130.69C101.32 151.11 76.1 151.1 61.31 130.67L0 46Z",
        "M113.12 69.37L115.22 66.49C130.87 44.9 156.4 45.68 170.7 68.18L189.31 97.44C200.84 115.58 199.82 137.73 215.67 126.3L213.57 129.17C198.67 149.53 174.45 148.74 160.91 127.45L141.09 96.28C129.64 78.27 128.81 57.95 113.12 69.37Z",
        "M213.49 64.4L215.59 61.52C231.34 40 256.71 40.99 270.74 63.66L321.71 146C290.37 146 271.7 141.91 268.73 137.12L240.79 91.98C229.56 73.83 229.23 53.05 213.49 64.4Z",
    )
}
