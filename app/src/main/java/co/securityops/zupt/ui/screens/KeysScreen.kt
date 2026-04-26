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

package co.securityops.zupt.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import co.securityops.zupt.core.crypto.HybridKem
import co.securityops.zupt.core.io.SafFiles
import co.securityops.zupt.ui.components.*
import co.securityops.zupt.ui.theme.*
import co.securityops.zupt.util.toHex
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun KeysScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var publicBytes by remember { mutableStateOf<ByteArray?>(null) }
    var privateBytes by remember { mutableStateOf<ByteArray?>(null) }
    var publicHex by remember { mutableStateOf<String?>(null) }
    var privateHex by remember { mutableStateOf<String?>(null) }
    var generating by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf<String?>(null) }
    var status by remember { mutableStateOf<Pair<String, Color>?>(null) }

    val savePublic = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri: Uri? ->
        val bytes = publicBytes
        if (uri != null && bytes != null) {
            scope.launch(Dispatchers.IO) {
                try {
                    val hex = bytes.toHex().toByteArray(Charsets.US_ASCII)
                    SafFiles.writeBytes(ctx, uri, hex)
                    val verify = SafFiles.readBytes(ctx, uri, sizeCap = hex.size.toLong() + 1024)
                    if (!verify.contentEquals(hex)) {
                        status = ("Save verification FAILED — provider corrupted the write. Try Downloads." to RedFail)
                    } else {
                        status = "Public key saved & verified — ${bytes.size} bytes" to GreenOk
                    }
                } catch (t: Throwable) {
                    status = "Save failed: ${t.message}" to RedFail
                }
            }
        }
    }

    val savePrivate = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri: Uri? ->
        val bytes = privateBytes
        if (uri != null && bytes != null) {
            scope.launch(Dispatchers.IO) {
                try {
                    val hex = bytes.toHex().toByteArray(Charsets.US_ASCII)
                    SafFiles.writeBytes(ctx, uri, hex)
                    val verify = SafFiles.readBytes(ctx, uri, sizeCap = hex.size.toLong() + 1024)
                    if (!verify.contentEquals(hex)) {
                        status = ("Save verification FAILED — provider corrupted the write. Try Downloads." to RedFail)
                    } else {
                        status = "Private key saved & verified — ${bytes.size} bytes" to GreenOk
                    }
                } catch (t: Throwable) {
                    status = "Save failed: ${t.message}" to RedFail
                }
            }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionCard(
            title = "Post-Quantum Keys",
            subtitle = "Generate an ML-KEM-768 + X25519 hybrid keypair. Download each key as a text file to a location of your choice. Nothing leaves your device.",
            accent = Mg0
        ) {
            GlowButton(
                text = if (generating) "Generating…" else "Generate Keypair",
                enabled = !generating,
                accent = Mg0,
                onClick = {
                    scope.launch {
                        generating = true
                        err = null
                        status = null
                        try {
                            val kp = withContext(Dispatchers.Default) { HybridKem.generateKeypair() }
                            publicBytes = kp.publicKey
                            privateBytes = kp.privateKey
                            publicHex = kp.publicKey.toHex()
                            privateHex = kp.privateKey.toHex()
                        } catch (t: Throwable) {
                            err = "${t.javaClass.simpleName}: ${t.message ?: "key generation failed"}"
                        } finally {
                            generating = false
                        }
                    }
                }
            )
            err?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = RedFail, style = MaterialTheme.typography.bodySmall)
            }
            status?.let { (m, c) ->
                Spacer(Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Check, null, tint = c, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(m, color = c, style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        if (publicHex != null && privateHex != null) {
            KeyBlock(
                title = "Public Key",
                subtitle = "Share freely. Used to encrypt archives addressed to you.",
                hex = publicHex!!,
                sizeBytes = publicBytes!!.size,
                accent = Cy0,
                fileName = "zupt-public.key",
                onDownload = { savePublic.launch("zupt-public.key") }
            )
            KeyBlock(
                title = "Private Key",
                subtitle = "Keep SECRET. Required to decrypt archives. If lost, encrypted data is unrecoverable.",
                hex = privateHex!!,
                sizeBytes = privateBytes!!.size,
                accent = Mg0,
                fileName = "zupt-private.key",
                onDownload = { savePrivate.launch("zupt-private.key") },
                warn = true
            )
        }
    }
}

@Composable
private fun KeyBlock(
    title: String,
    subtitle: String,
    hex: String,
    sizeBytes: Int,
    accent: Color,
    fileName: String,
    onDownload: () -> Unit,
    warn: Boolean = false
) {
    SectionCard(title = title, subtitle = subtitle, accent = accent) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "$sizeBytes bytes · ${hex.length} hex chars",
                color = Ink2,
                style = MaterialTheme.typography.labelMedium
            )
            Spacer(Modifier.weight(1f))
            Text(fileName, color = accent, style = MaterialTheme.typography.bodySmall)
        }
        Spacer(Modifier.height(10.dp))

        val preview = if (hex.length > 128) {
            hex.substring(0, 64).chunked(4).joinToString(" ") + "\n…\n" +
                hex.substring(hex.length - 64).chunked(4).joinToString(" ")
        } else {
            hex.chunked(4).joinToString(" ")
        }
        SelectionContainer {
            Text(
                text = preview,
                color = Ink1,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(10.dp))
                    .background(Bg2)
                    .border(1.dp, StrokeWeak, RoundedCornerShape(10.dp))
                    .padding(14.dp)
            )
        }

        Spacer(Modifier.height(14.dp))

        GlowButton(
            text = "Download $title",
            accent = accent,
            onClick = onDownload,
            leading = {
                Icon(
                    Icons.Default.Download,
                    contentDescription = null,
                    tint = Bg0,
                    modifier = Modifier.size(18.dp)
                )
            }
        )

        if (warn) {
            Spacer(Modifier.height(12.dp))
            Row(verticalAlignment = Alignment.Top) {
                Icon(Icons.Default.Warning, null, tint = Amber, modifier = Modifier.size(14.dp))
                Spacer(Modifier.width(6.dp))
                Text(
                    "Anyone with this file can decrypt your archives. Store offline (hardware key, encrypted USB, paper backup). Never share.",
                    color = Amber,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}
