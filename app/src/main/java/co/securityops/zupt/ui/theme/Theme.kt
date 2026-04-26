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

import android.app.Activity
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val ZuptColors = darkColorScheme(
    primary = Cy0,
    onPrimary = Bg0,
    primaryContainer = Bg3,
    onPrimaryContainer = Cy0,
    secondary = Mg0,
    onSecondary = Bg0,
    secondaryContainer = Bg3,
    onSecondaryContainer = Mg0,
    tertiary = Amber,
    onTertiary = Bg0,
    background = Bg0,
    onBackground = Ink0,
    surface = Bg1,
    onSurface = Ink0,
    surfaceVariant = Bg2,
    onSurfaceVariant = Ink1,
    surfaceContainer = Bg2,
    surfaceContainerHigh = Bg3,
    surfaceContainerHighest = Bg4,
    outline = StrokeMid,
    outlineVariant = StrokeWeak,
    error = RedFail,
    onError = Color.Black,
    scrim = Color(0xCC000000)
)

@Composable
fun ZuptTheme(content: @Composable () -> Unit) {
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = Color.Transparent.toArgb()
            window.navigationBarColor = Color.Transparent.toArgb()
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = false
                isAppearanceLightNavigationBars = false
            }
        }
    }
    MaterialTheme(
        colorScheme = ZuptColors,
        typography = ZuptTypography,
        content = content
    )
}
