package com.viadere.verify

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The pure logic of the Android button: session links, the hand-off rule, the panel, the return check and the QR encoder. */
class VerifyModelTest {
    private val link = "https://viadere.com/v/K7QFM2XA"

    @Test
    fun onlyAViadereSessionLinkMakesASession() {
        val session = VerifySession.parse(link, expiresAtMillis = 1_000)!!
        assertEquals("K7QFM2XA", session.code)
        assertEquals("K7QF-M2XA", session.displayCode)
        assertEquals("K 7 Q F M 2 X A", session.spokenCode)
        assertTrue(session.isExpired(1_000))
        assertFalse(session.isExpired(999))
        assertNotNull(VerifySession.parse("https://viadere.cksites.dev/v/K7QFM2XA"))
        listOf(
            "http://viadere.com/v/K7QFM2XA", "https://evil.test/v/K7QFM2XA", "https://viadere.com.evil.test/v/K7QFM2XA", "https://viadere.com:443/v/K7QFM2XA",
            "https://user@viadere.com/v/K7QFM2XA", "https://viadere.com/v/K7QFM2XA?next=x", "https://viadere.com/v/K7QFM2XA#x", "https://viadere.com/v/k7qfm2xa",
            "https://viadere.com/v/K7QFM2X1", "https://viadere.com/k/K7QFM2XA", "https://www.viadere.com/v/K7QFM2XA", "intent://v/K7QFM2XA", "",
        ).forEach { assertNull(it, VerifySession.parse(it)) }
        assertNull(VerifySession.parse("https://viadere.cksites.dev/v/K7QFM2XA", allowedHosts = setOf("viadere.com")))
    }

    @Test
    fun phonesHandOffAndComputersShowTheQrFirst() {
        val session = VerifySession.parse(link, expiresAtMillis = 10_000)!!
        assertEquals(VerifyAction.OpenInApp(link), VerifyHandoff.onTap(VerifyDevice.HANDHELD, session, 0))
        assertEquals(VerifyAction.ShowPanel, VerifyHandoff.onTap(VerifyDevice.COMPUTER, session, 0))
        assertEquals(VerifyAction.Expired, VerifyHandoff.onTap(VerifyDevice.HANDHELD, session, 10_000))
        assertEquals(VerifyAction.HandedOff, VerifyHandoff.afterOpenInApp(true))
        assertEquals(VerifyAction.ShowPanel, VerifyHandoff.afterOpenInApp(false))
    }

    @Test
    fun thePanelStartsWithTheQrAndOffersTheOtherOptions() {
        val session = VerifySession.parse(link)!!
        val panel = VerifyPanelState.initial(session, sendToPhone = false)
        assertEquals(VerifyPanelState.Screen.QR, panel.screen)
        assertEquals(listOf(VerifyOption.OPEN_ON_THIS_DEVICE, VerifyOption.ENTER_CODE, VerifyOption.GET_APP), panel.options)
        assertEquals(VerifyPanelState.Effect.None, panel.select(VerifyOption.SEND_TO_PHONE).second)
        val options = panel.chooseAnotherOption()
        assertEquals(VerifyPanelState.Screen.OPTIONS, options.screen)
        assertEquals(VerifyPanelState.Effect.Open(link), options.select(VerifyOption.OPEN_ON_THIS_DEVICE).second)
        val (coded, effect) = options.select(VerifyOption.ENTER_CODE)
        assertEquals(VerifyPanelState.Effect.None, effect)
        assertTrue(coded.showsCode)
        assertEquals("Your code is K 7 Q F M 2 X A.", coded.status)
        val back = coded.backToQr()
        assertEquals(VerifyPanelState.Screen.QR, back.screen)
        assertFalse(back.showsCode)
        assertNull(back.status)
        val withPhone = VerifyPanelState.initial(session, sendToPhone = true)
        assertTrue(VerifyOption.SEND_TO_PHONE in withPhone.options)
        assertEquals(VerifyPanelState.Effect.SendToPhone, withPhone.select(VerifyOption.SEND_TO_PHONE).second)
    }

    @Test
    fun theReturnIsRecognisedOnlyOnTheExpectedUrl() {
        val expected = "https://shop.northwind.example/checkout?step=2"
        assertTrue(VerifyReturn.isReturn("https://shop.northwind.example/checkout?step=2", expected))
        listOf("https://evil.test/checkout", "http://shop.northwind.example/checkout", "https://shop.northwind.example/other",
               "https://user@shop.northwind.example/checkout", "https://shop.northwind.example:444/checkout", "https://shop.northwind.example/checkout#x")
            .forEach { assertFalse(it, VerifyReturn.isReturn(it, expected)) }
    }

    @Test
    fun theColoursMatchTheBrandAndTheWebButton() {
        assertEquals(VerifyColors(0x1F1E1CL, 0xF5F2ECL, 0x1F1E1CL), VerifyColors.of(VerifyVariant.FILLED, dark = false))
        assertEquals(VerifyColors(0xF3F0EAL, 0x1F1E1CL, 0xF3F0EAL), VerifyColors.of(VerifyVariant.FILLED, dark = true))
        assertNull(VerifyColors.of(VerifyVariant.OUTLINE, dark = false).background)
        assertTrue(VerifySize.entries.all { it.minimumTouchTargetDp >= 48 })
        assertEquals("Verify with Viadere", VerifyFlow.VERIFY.label)
    }

    private fun rows(matrix: Array<BooleanArray>?): List<String> = matrix!!.map { row -> row.joinToString("") { if (it) "1" else "0" } }

    @Test
    fun theQrEncoderMatchesTheCrossCheckedVectors() {
        assertEquals(QrVectors.SESSION_LINK, rows(QrCode.matrix(QrVectors.SESSION_LINK_TEXT)))
        assertEquals(QrVectors.SINGLE_BYTE, rows(QrCode.matrix(QrVectors.SINGLE_BYTE_TEXT)))
        assertEquals(QrVectors.VERSION_7, rows(QrCode.matrix(QrVectors.VERSION_7_TEXT)))
        assertEquals(29, QrCode.matrix(link)!!.size)
        assertNull("beyond version 10", QrCode.matrix("x".repeat(400)))
    }
}
