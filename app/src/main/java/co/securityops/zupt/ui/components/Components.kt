/*
 * Zupt for Android — post-quantum encrypted file compression
 * Copyright (C) 2026 Cristian Cezar Moisés
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package co.securityops.zupt.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import co.securityops.zupt.ui.theme.*

/** Primary CTA with animated cyan glow on press. */
@Composable
fun GlowButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    accent: Color = Cy0,
    leading: (@Composable () -> Unit)? = null
) {
    val interactionSource = remember { MutableInteractionSource() }
    val pressed by interactionSource.collectIsPressedAsState()
    val scale by animateFloatAsState(if (pressed) 0.98f else 1f, label = "scale")
    val glow by animateFloatAsState(
        if (pressed) 0.55f else if (enabled) 0.30f else 0f,
        animationSpec = tween(220), label = "glow"
    )

    Box(
        modifier = modifier
            .fillMaxWidth()
            .height(54.dp)
            .graphicsLayer { scaleX = scale; scaleY = scale }
            .drawBehind {
                if (glow > 0f) drawRoundRect(
                    color = accent.copy(alpha = glow * 0.4f),
                    cornerRadius = CornerRadius(28f, 28f),
                    style = Stroke(width = 2f + glow * 20f),
                    topLeft = androidx.compose.ui.geometry.Offset(-glow * 6f, -glow * 6f),
                    size = Size(size.width + glow * 12f, size.height + glow * 12f)
                )
            }
            .clip(RoundedCornerShape(14.dp))
            .background(if (enabled) accent else Bg4)
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                enabled = enabled,
                onClick = onClick
            ),
        contentAlignment = Alignment.Center
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            leading?.invoke()
            if (leading != null) Spacer(Modifier.width(10.dp))
            Text(
                text.uppercase(),
                color = Bg0,
                fontWeight = FontWeight.Black,
                fontSize = 13.sp,
                letterSpacing = 2.sp
            )
        }
    }
}

/** Dashed cyan drop zone. */
@Composable
fun DropZone(
    label: String,
    filename: String?,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    accent: Color = Cy0
) {
    val picked = filename != null
    Box(
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 120.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(Bg2)
            .dashedBorder(accent.copy(alpha = if (picked) 0.6f else 0.25f), 14.dp)
            .clickable { onClick() }
            .padding(24.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                imageVector = if (picked) Icons.Default.CheckCircle else Icons.Default.CloudUpload,
                contentDescription = null,
                tint = if (picked) GreenOk else accent,
                modifier = Modifier.size(32.dp)
            )
            Spacer(Modifier.height(10.dp))
            Text(
                text = filename ?: label,
                color = if (picked) Ink0 else Ink1,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (picked) FontWeight.SemiBold else FontWeight.Normal
            )
            if (!picked) {
                Spacer(Modifier.height(4.dp))
                Text(
                    "TAP TO BROWSE",
                    color = accent.copy(alpha = 0.55f),
                    style = MaterialTheme.typography.labelMedium
                )
            }
        }
    }
}

/** Hex-only input field, monospace. */
@Composable
fun HexKeyField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    placeholder: String = "abcd 0123 ..."
) {
    Column(modifier) {
        Text(
            label.uppercase(),
            color = Ink2,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(bottom = 6.dp)
        )
        BasicTextField(
            value = value,
            onValueChange = { onChange(it.filter { c -> c.isLetterOrDigit() || c.isWhitespace() }) },
            textStyle = TextStyle(
                color = Ink0, fontSize = 12.sp, fontFamily = Mono
            ),
            cursorBrush = SolidColor(Cy0),
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(Bg2)
                .border(1.dp, StrokeMid, RoundedCornerShape(10.dp))
                .padding(horizontal = 14.dp, vertical = 12.dp),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
            decorationBox = { inner ->
                if (value.isEmpty()) Text(
                    placeholder,
                    color = Ink3,
                    style = TextStyle(fontSize = 12.sp, fontFamily = Mono)
                )
                inner()
            }
        )
    }
}

@Composable
fun PasswordField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier
) {
    var reveal by remember { mutableStateOf(false) }
    Column(modifier) {
        Text(
            label.uppercase(),
            color = Ink2,
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(bottom = 6.dp)
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(Bg2)
                .border(1.dp, StrokeMid, RoundedCornerShape(10.dp))
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            BasicTextField(
                value = value,
                onValueChange = onChange,
                textStyle = TextStyle(color = Ink0, fontSize = 14.sp, fontFamily = Mono),
                cursorBrush = SolidColor(Cy0),
                visualTransformation = if (reveal) VisualTransformation.None else PasswordVisualTransformation('•'),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.weight(1f),
                decorationBox = { inner ->
                    if (value.isEmpty()) Text("•••••",
                        color = Ink3,
                        style = TextStyle(fontSize = 14.sp, fontFamily = Mono))
                    inner()
                }
            )
            Icon(
                imageVector = if (reveal) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                contentDescription = null,
                tint = Ink2,
                modifier = Modifier
                    .size(22.dp)
                    .clickable { reveal = !reveal }
            )
        }
    }
}

/** Titled outlined card. */
@Composable
fun SectionCard(
    title: String,
    subtitle: String? = null,
    modifier: Modifier = Modifier,
    accent: Color = Cy0,
    content: @Composable ColumnScope.() -> Unit
) {
    Column(
        modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .background(Bg1)
            .border(1.dp, StrokeWeak, RoundedCornerShape(18.dp))
            .padding(20.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(8.dp)
                    .clip(RoundedCornerShape(50))
                    .background(accent)
            )
            Spacer(Modifier.width(10.dp))
            Text(
                title,
                color = Ink0,
                style = MaterialTheme.typography.headlineMedium
            )
        }
        if (subtitle != null) {
            Spacer(Modifier.height(6.dp))
            Text(
                subtitle,
                color = Ink1,
                style = MaterialTheme.typography.bodyMedium
            )
        }
        Spacer(Modifier.height(16.dp))
        content()
    }
}

@Composable
fun StatusPill(label: String, tone: Color = Cy0) {
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .border(1.dp, tone.copy(alpha = 0.5f), RoundedCornerShape(50))
            .background(Bg2)
            .padding(horizontal = 14.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        val infinite = rememberInfiniteTransition(label = "pulse")
        val alpha by infinite.animateFloat(
            initialValue = 0.3f, targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = tween(1200, easing = FastOutSlowInEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "pulse"
        )
        Box(
            Modifier
                .size(8.dp)
                .clip(RoundedCornerShape(50))
                .background(tone.copy(alpha = alpha))
        )
        Spacer(Modifier.width(8.dp))
        Text(label.uppercase(), color = tone, style = MaterialTheme.typography.labelMedium)
    }
}

@Composable
fun StatRow(key: String, value: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(key.uppercase(), color = Ink2, style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.weight(1f))
        Text(value, color = Ink0, style = MaterialTheme.typography.bodySmall)
    }
}

/** Modifier ext: cheap dashed border using drawBehind. */
fun Modifier.dashedBorder(color: Color, radius: androidx.compose.ui.unit.Dp): Modifier =
    this.drawBehind {
        val stroke = Stroke(
            width = 2f,
            pathEffect = androidx.compose.ui.graphics.PathEffect.dashPathEffect(
                floatArrayOf(18f, 12f), 0f
            )
        )
        drawRoundRect(
            color = color,
            cornerRadius = CornerRadius(radius.toPx(), radius.toPx()),
            style = stroke
        )
    }

/**
 * Key input with two paths: (1) tap "Upload" to pick a key file (SAF) — key is
 * parsed from hex text; or (2) type/paste hex manually.
 *
 * Designed for PQ public keys in Compress and PQ private keys in Extract.
 */
@Composable
fun KeyUploadField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    filename: String?,
    onUploadClick: () -> Unit,
    modifier: Modifier = Modifier,
    accent: Color = Mg0
) {
    Column(modifier) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                label.uppercase(),
                color = Ink2,
                style = MaterialTheme.typography.labelMedium
            )
            Spacer(Modifier.weight(1f))
            Row(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(Bg3)
                    .border(1.dp, accent.copy(alpha = 0.45f), RoundedCornerShape(8.dp))
                    .clickable { onUploadClick() }
                    .padding(horizontal = 10.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.UploadFile,
                    contentDescription = null,
                    tint = accent,
                    modifier = Modifier.size(14.dp)
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    "UPLOAD",
                    color = accent,
                    style = MaterialTheme.typography.labelMedium
                )
            }
        }
        Spacer(Modifier.height(6.dp))

        if (filename != null) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.CheckCircle,
                    null,
                    tint = GreenOk,
                    modifier = Modifier.size(12.dp)
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    "Loaded: $filename",
                    color = GreenOk,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        BasicTextField(
            value = value,
            onValueChange = { onChange(it.filter { c -> c.isLetterOrDigit() || c.isWhitespace() }) },
            textStyle = androidx.compose.ui.text.TextStyle(
                color = Ink0, fontSize = 12.sp, fontFamily = Mono
            ),
            cursorBrush = SolidColor(accent),
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(Bg2)
                .border(1.dp, StrokeMid, RoundedCornerShape(10.dp))
                .padding(horizontal = 14.dp, vertical = 12.dp),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii),
            decorationBox = { inner ->
                if (value.isEmpty()) Text(
                    "or paste hex: abcd 0123 …",
                    color = Ink3,
                    style = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, fontFamily = Mono)
                )
                inner()
            }
        )
    }
}
