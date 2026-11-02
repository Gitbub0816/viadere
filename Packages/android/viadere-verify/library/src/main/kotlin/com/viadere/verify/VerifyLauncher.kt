package com.viadere.verify

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri

/** Opens session links: in the Viadere app only (App Link hand-off), or normally (the panel's options). */
object VerifyLauncher {
    /**
     * Opens [link] **only if a non-browser app is the verified handler** (`FLAG_ACTIVITY_REQUIRE_NON_BROWSER`, API 30+): the Viadere app when it is
     * installed and verified for the link domain. Returns `false` when no such app exists, so the caller shows the QR-first panel instead of a
     * browser tab.
     */
    fun openInApp(context: Context, link: String): Boolean {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(link))
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_REQUIRE_NON_BROWSER)
        return try {
            context.startActivity(intent)
            true
        } catch (_: ActivityNotFoundException) {
            false
        }
    }

    /** Opens [link] the ordinary way (the Viadere app if it claims it, otherwise the landing page with the store link). */
    fun open(context: Context, link: String) {
        try {
            context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(link)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: ActivityNotFoundException) {
            // No browser at all: nothing sensible to do; the panel still shows the QR code and the typed code.
        }
    }

    /** ChromeOS and desktop windows get the QR first; phones and tablets hand off. */
    fun device(context: Context): VerifyDevice =
        if (context.packageManager.hasSystemFeature(PackageManager.FEATURE_PC)) VerifyDevice.COMPUTER else VerifyDevice.HANDHELD
}
