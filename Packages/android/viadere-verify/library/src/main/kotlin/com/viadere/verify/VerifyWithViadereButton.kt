package com.viadere.verify

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.scale
import androidx.compose.ui.graphics.drawscope.translate
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import kotlinx.coroutines.launch

private fun rgb(hex: Long): Color = Color(0xFF000000L or hex)

/** The monochrome Viadere mark in [color] (decorative: no semantics). */
@Composable
fun VerifyWithViadereMark(color: Color, modifier: Modifier = Modifier) {
    val back = remember { PathParser().parsePathString(VerifyMark.BACK).toPath() }
    val front = remember { VerifyMark.FRONT.map { PathParser().parsePathString(it).toPath() } }
    Canvas(modifier.aspectRatio(VerifyMark.WIDTH / VerifyMark.HEIGHT).clearAndSetSemantics {}) {
        val s = minOf(size.width / VerifyMark.WIDTH, size.height / VerifyMark.HEIGHT)
        scale(s, s, pivot = Offset.Zero) {
            drawPath(back, color.copy(alpha = VerifyMark.BACK_ALPHA))
            front.forEach { drawPath(it, color) }
            drawCircle(color, radius = VerifyMark.DOT_R, center = Offset(VerifyMark.DOT_X, VerifyMark.DOT_Y))
        }
    }
}

/**
 * The "Verify with Viadere" button.
 *
 * ```
 * VerifyWithViadereButton(session = VerifySession.parse(linkFromYourServer)!!, onSendToPhone = { yourServer.sendToPhone() })
 * ```
 * On a phone it opens the session in the Viadere app (App Link, never a browser); when that is not possible it shows the QR-first panel.
 *
 * @param onSendToPhone offer "Send to my phone" (your server creates an ordinary verification request for this connected customer). `null`
 *   hides it.
 * @param onExpired the code expired: get a new session from your server.
 */
@Composable
fun VerifyWithViadereButton(
    session: VerifySession,
    modifier: Modifier = Modifier,
    flow: VerifyFlow = VerifyFlow.VERIFY,
    variant: VerifyVariant = VerifyVariant.FILLED,
    size: VerifySize = VerifySize.MEDIUM,
    display: VerifyDisplay = VerifyDisplay.LABEL,
    dark: Boolean = isSystemInDarkTheme(),
    onSendToPhone: (suspend () -> Unit)? = null,
    onExpired: (() -> Unit)? = null,
) {
    val context = LocalContext.current
    var panel by remember { mutableStateOf<VerifyPanelState?>(null) }
    val colors = VerifyColors.of(variant, dark)
    val shape = CircleShape
    val iconOnly = display == VerifyDisplay.ICON_ONLY
    Box(
        modifier
            .sizeIn(minWidth = size.minimumTouchTargetDp.dp, minHeight = size.minimumTouchTargetDp.dp)
            .clickable(role = Role.Button, onClickLabel = flow.label) {
                when (val action = VerifyHandoff.onTap(VerifyLauncher.device(context), session, System.currentTimeMillis())) {
                    is VerifyAction.OpenInApp ->
                        if (VerifyHandoff.afterOpenInApp(VerifyLauncher.openInApp(context, action.link)) == VerifyAction.ShowPanel) {
                            panel = VerifyPanelState.initial(session, onSendToPhone != null)
                        }
                    VerifyAction.ShowPanel -> panel = VerifyPanelState.initial(session, onSendToPhone != null)
                    VerifyAction.Expired -> onExpired?.invoke()
                    VerifyAction.HandedOff -> Unit
                }
            }
            .semantics { contentDescription = flow.label },
        contentAlignment = Alignment.Center,
    ) {
        Row(
            Modifier
                .height(size.heightDp.dp)
                .then(if (iconOnly) Modifier.width(size.heightDp.dp) else Modifier.widthIn(min = size.heightDp.dp))
                .background(colors.background?.let(::rgb) ?: Color.Transparent, shape)
                .border(BorderStroke(1.dp, rgb(colors.border)), shape)
                .padding(horizontal = if (iconOnly) 0.dp else (size.heightDp * 0.45f).dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy((size.fontSp * 0.55f).dp, Alignment.CenterHorizontally),
        ) {
            VerifyWithViadereMark(rgb(colors.foreground), Modifier.width((size.fontSp * if (iconOnly) 1.75f else 2f).dp))
            if (!iconOnly) {
                BasicText(flow.label, style = TextStyle(color = rgb(colors.foreground), fontSize = size.fontSp.sp, fontWeight = FontWeight.SemiBold),
                          maxLines = 1, modifier = Modifier.clearAndSetSemantics {})
            }
        }
    }
    panel?.let { state ->
        VerifyPanel(state = state, flow = flow, dark = dark, onSendToPhone = onSendToPhone, onState = { panel = it }, onDismiss = { panel = null })
    }
}

/** The QR-first panel: the QR code, a short explanation and "Choose another option". */
@Composable
fun VerifyPanel(
    state: VerifyPanelState,
    flow: VerifyFlow = VerifyFlow.VERIFY,
    dark: Boolean = isSystemInDarkTheme(),
    onSendToPhone: (suspend () -> Unit)?,
    onState: (VerifyPanelState) -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val surface = rgb(if (dark) 0x1C1B1AL else 0xFCFBF8L)
    val text = rgb(if (dark) 0xF3F0EAL else 0x1F1E1CL)
    val secondary = rgb(if (dark) 0xA29D94L else 0x6B675FL)
    val hairline = rgb(if (dark) 0x4A4844L else 0xC9C4BBL)
    val raised = rgb(if (dark) 0x262523L else 0xFFFFFFL)
    val body = TextStyle(color = text, fontSize = 15.sp)
    val small = TextStyle(color = secondary, fontSize = 13.sp)
    val strong = body.copy(fontWeight = FontWeight.SemiBold)

    @Composable
    fun Secondary(label: String, onClick: () -> Unit) {
        Box(
            Modifier.fillMaxWidth().heightIn(min = 48.dp).border(1.dp, text, CircleShape).clickable(role = Role.Button, onClick = onClick),
            contentAlignment = Alignment.Center,
        ) { BasicText(label, style = strong) }
    }

    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Column(
            Modifier
                .padding(16.dp)
                .widthIn(max = 380.dp)
                .background(surface, RoundedCornerShape(20.dp))
                .border(1.dp, hairline, RoundedCornerShape(20.dp))
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 22.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                VerifyWithViadereMark(text, Modifier.width(34.dp))
                BasicText(flow.title, style = strong.copy(fontSize = 17.sp), modifier = Modifier.weight(1f).semantics { heading() })
                Box(
                    Modifier.size(48.dp).clickable(role = Role.Button, onClickLabel = "Close", onClick = onDismiss).semantics { contentDescription = "Close" },
                    contentAlignment = Alignment.Center,
                ) { BasicText("×", style = body.copy(fontSize = 26.sp), modifier = Modifier.clearAndSetSemantics {}) }
            }
            when (state.screen) {
                VerifyPanelState.Screen.QR -> {
                    BasicText(flow.scanPrompt, style = strong)
                    val matrix = remember(state.session.link) { QrCode.matrix(state.session.link) }
                    if (matrix != null) {
                        Box(
                            Modifier.fillMaxWidth(),
                            contentAlignment = Alignment.Center,
                        ) {
                            Canvas(
                                Modifier
                                    .widthIn(max = 248.dp)
                                    .fillMaxWidth()
                                    .aspectRatio(1f)
                                    .background(Color.White, RoundedCornerShape(14.dp))
                                    .border(1.dp, hairline, RoundedCornerShape(14.dp))
                                    .padding(8.dp)
                                    .semantics { contentDescription = "QR code to continue in the Viadere app" },
                            ) { drawQr(matrix) }
                        }
                    }
                    BasicText(flow.explanation, style = small)
                    Secondary("Choose another option") { onState(state.chooseAnotherOption()) }
                }
                VerifyPanelState.Screen.OPTIONS -> {
                    state.options.forEach { option ->
                        Column(
                            Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .background(raised, RoundedCornerShape(14.dp))
                                .border(1.dp, hairline, RoundedCornerShape(14.dp))
                                .clickable(role = Role.Button) {
                                    val (next, effect) = state.select(option)
                                    onState(next)
                                    when (effect) {
                                        is VerifyPanelState.Effect.Open -> VerifyLauncher.open(context, effect.link)
                                        VerifyPanelState.Effect.SendToPhone -> onSendToPhone?.let { send -> scope.launch { send() } }
                                        VerifyPanelState.Effect.None -> Unit
                                    }
                                }
                                .padding(horizontal = 14.dp, vertical = 12.dp),
                        ) {
                            BasicText(option.title, style = strong)
                            BasicText(option.detail, style = small)
                        }
                    }
                    if (state.showsCode) {
                        Column(Modifier.fillMaxWidth().background(raised, RoundedCornerShape(14.dp)).padding(14.dp)) {
                            BasicText("Open Viadere, choose Enter code and type", style = body)
                            Spacer(Modifier.height(4.dp))
                            BasicText(
                                state.session.displayCode,
                                style = strong.copy(fontSize = 22.sp, fontFamily = FontFamily.Monospace, letterSpacing = 2.sp),
                                modifier = Modifier.semantics { contentDescription = state.session.spokenCode },
                            )
                        }
                    }
                    Secondary("Back to the QR code") { onState(state.backToQr()) }
                }
            }
            state.status?.let { BasicText(it, style = small, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
        }
    }
}

private fun DrawScope.drawQr(matrix: Array<BooleanArray>) {
    val quiet = 4 // the four-module quiet zone ISO/IEC 18004 asks for
    val count = matrix.size + quiet * 2
    val cell = minOf(size.width, size.height) / count
    translate(left = (size.width - cell * count) / 2, top = (size.height - cell * count) / 2) {
        for (y in matrix.indices) for (x in matrix.indices) {
            if (matrix[y][x]) drawRect(Color(0xFF1F1E1CL), topLeft = Offset((x + quiet) * cell, (y + quiet) * cell), size = Size(cell, cell))
        }
    }
}
