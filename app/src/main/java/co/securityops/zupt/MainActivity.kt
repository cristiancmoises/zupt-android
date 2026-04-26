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

package co.securityops.zupt

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import co.securityops.zupt.ui.screens.*
import co.securityops.zupt.ui.theme.*

enum class Tab(val title: String, val icon: ImageVector) {
    KEYS("Keys", Icons.Default.Key),
    COMPRESS("Compress", Icons.Default.Archive),
    EXTRACT("Extract", Icons.Default.FolderOpen),
    VERIFY("Verify", Icons.Default.Shield),
    INFO("Info", Icons.Default.Info),
    ABOUT("About", Icons.Default.Code)
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContent {
            ZuptTheme {
                App()
            }
        }
    }
}

@Composable
private fun App() {
    var current by remember { mutableStateOf(Tab.COMPRESS) }

    Scaffold(
        containerColor = Bg0,
        contentColor = Ink0,
        topBar = { TopBar(current) },
        bottomBar = { BottomRail(current) { current = it } }
    ) { inner ->
        Box(modifier = Modifier.fillMaxSize().padding(inner)) {
            when (current) {
                Tab.KEYS -> KeysScreen()
                Tab.COMPRESS -> CompressScreen()
                Tab.EXTRACT -> ExtractScreen()
                Tab.VERIFY -> VerifyScreen()
                Tab.INFO -> InfoScreen()
                Tab.ABOUT -> AboutScreen()
            }
        }
    }
}

@Composable
private fun TopBar(current: Tab) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Bg0)
            .statusBarsPadding()
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text("ZUPT",
            color = Cy0,
            style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.width(10.dp))
        Text("POST-QUANTUM BACKUP",
            color = Ink2,
            style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.weight(1f))
        co.securityops.zupt.ui.components.StatusPill("OFFLINE", tone = Cy0)
    }
}

@Composable
private fun BottomRail(current: Tab, onSelect: (Tab) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Bg1)
            .navigationBarsPadding()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 8.dp, vertical = 10.dp),
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Tab.values().forEach { t ->
            TabChip(
                tab = t,
                selected = t == current,
                onClick = { onSelect(t) }
            )
        }
    }
}

@Composable
private fun TabChip(tab: Tab, selected: Boolean, onClick: () -> Unit) {
    Column(
        modifier = Modifier
            .clickable { onClick() }
            .padding(horizontal = 14.dp, vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = tab.icon,
            contentDescription = tab.title,
            tint = if (selected) Cy0 else Ink2,
            modifier = Modifier.size(22.dp)
        )
        Spacer(Modifier.height(4.dp))
        Text(
            tab.title.uppercase(),
            color = if (selected) Cy0 else Ink2,
            style = MaterialTheme.typography.labelMedium
        )
    }
}
