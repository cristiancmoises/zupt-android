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

package co.securityops.zupt.ui.theme

import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// System monospace + sans fallback. Keeps APK tiny.
// For perfect zupt-web parity you can drop Orbitron/IBMPlexSans/JetBrainsMono .ttf
// into res/font/ and point the FontFamily here — build will pick them up automatically.
val Mono = FontFamily.Monospace
val Sans = FontFamily.SansSerif

val ZuptTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = Mono,
        fontWeight = FontWeight.Black,
        fontSize = 40.sp,
        letterSpacing = 2.sp,
        lineHeight = 46.sp
    ),
    displayMedium = TextStyle(
        fontFamily = Mono,
        fontWeight = FontWeight.Bold,
        fontSize = 28.sp,
        letterSpacing = 1.5.sp,
        lineHeight = 34.sp
    ),
    headlineMedium = TextStyle(
        fontFamily = Mono,
        fontWeight = FontWeight.Bold,
        fontSize = 22.sp,
        letterSpacing = 1.sp
    ),
    titleLarge = TextStyle(
        fontFamily = Mono,
        fontWeight = FontWeight.SemiBold,
        fontSize = 18.sp,
        letterSpacing = 0.6.sp
    ),
    titleMedium = TextStyle(
        fontFamily = Sans,
        fontWeight = FontWeight.SemiBold,
        fontSize = 15.sp
    ),
    bodyLarge = TextStyle(
        fontFamily = Sans,
        fontWeight = FontWeight.Normal,
        fontSize = 15.sp,
        lineHeight = 22.sp
    ),
    bodyMedium = TextStyle(
        fontFamily = Sans,
        fontWeight = FontWeight.Normal,
        fontSize = 13.sp,
        lineHeight = 19.sp
    ),
    bodySmall = TextStyle(
        fontFamily = Mono,
        fontWeight = FontWeight.Normal,
        fontSize = 11.sp,
        letterSpacing = 0.5.sp
    ),
    labelLarge = TextStyle(
        fontFamily = Mono,
        fontWeight = FontWeight.SemiBold,
        fontSize = 12.sp,
        letterSpacing = 2.sp
    ),
    labelMedium = TextStyle(
        fontFamily = Mono,
        fontWeight = FontWeight.Medium,
        fontSize = 10.sp,
        letterSpacing = 1.5.sp
    )
)
