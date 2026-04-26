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
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.documentfile.provider.DocumentFile
import co.securityops.zupt.core.archive.StreamingWriter
import co.securityops.zupt.core.codec.CodecId
import co.securityops.zupt.core.io.SafFiles
import co.securityops.zupt.ui.components.*
import co.securityops.zupt.ui.theme.*
import co.securityops.zupt.util.fromHex
import co.securityops.zupt.util.formatSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** One picked input — either a standalone file or a descendant of a picked folder. */
private data class PickedInput(
    val uri: Uri,
    val path: String,   // virtual path inside the archive (folder/file.ext)
    val size: Long
)

@Composable
fun CompressScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    val inputs = remember { mutableStateListOf<PickedInput>() }
    var codec by remember { mutableStateOf(CodecId.DEFLATE) }
    var level by remember { mutableStateOf(6f) }
    var password by remember { mutableStateOf("") }
    var pqPublic by remember { mutableStateOf("") }
    var pqKeyFilename by remember { mutableStateOf<String?>(null) }
    var running by remember { mutableStateOf(false) }
    var progressText by remember { mutableStateOf<String?>(null) }
    var lastMsg by remember { mutableStateOf<Pair<String, androidx.compose.ui.graphics.Color>?>(null) }
    var lastStats by remember { mutableStateOf<String?>(null) }

    // ─── Pickers ────────────────────────────────────────────────────────
    val filesPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        if (uris.isNotEmpty()) {
            scope.launch(Dispatchers.IO) {
                for (u in uris) {
                    try {
                        ctx.contentResolver.takePersistableUriPermission(
                            u, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
                        )
                    } catch (_: Throwable) { /* not all providers support persist */ }
                    val name = SafFiles.displayName(ctx, u) ?: "file"
                    val size = SafFiles.size(ctx, u).coerceAtLeast(0)
                    inputs += PickedInput(u, name, size)
                }
            }
        }
    }

    val folderPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { treeUri ->
        if (treeUri != null) {
            scope.launch(Dispatchers.IO) {
                try {
                    ctx.contentResolver.takePersistableUriPermission(
                        treeUri, android.content.Intent.FLAG_GRANT_READ_URI_PERMISSION
                    )
                } catch (_: Throwable) {}
                val root = DocumentFile.fromTreeUri(ctx, treeUri) ?: return@launch
                val rootName = root.name ?: "folder"
                walkTree(root, rootName) { doc, virtualPath ->
                    inputs += PickedInput(doc.uri, virtualPath, doc.length().coerceAtLeast(0))
                }
            }
        }
    }

    val keyPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            scope.launch(Dispatchers.IO) {
                try {
                    val raw = SafFiles.readBytes(ctx, uri, sizeCap = 64 * 1024)
                    pqPublic = String(raw, Charsets.US_ASCII).trim()
                    pqKeyFilename = SafFiles.displayName(ctx, uri)
                } catch (t: Throwable) {
                    lastMsg = "Key load failed: ${t.message}" to RedFail
                }
            }
        }
    }

    val saver = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { outUri ->
        if (outUri != null && inputs.isNotEmpty()) {
            scope.launch {
                running = true; lastMsg = null; lastStats = null
                progressText = "Starting…"
                try {
                    val result = withContext(Dispatchers.IO) {
                        val pqPub = if (pqPublic.isNotBlank()) pqPublic.fromHex() else null
                        val pwChars = if (password.isNotBlank()) password.toCharArray() else null
                        val fileInputs = inputs.map { pi ->
                            StreamingWriter.FileInput(
                                path = pi.path,
                                size = pi.size,
                                openStream = { ctx.contentResolver.openInputStream(pi.uri)!! }
                            )
                        }
                        ctx.contentResolver.openOutputStream(outUri, "w")!!.use { outStream ->
                            StreamingWriter.writeMulti(
                                output = outStream,
                                scratchDir = ctx.cacheDir,
                                opts = StreamingWriter.MultiOptions(
                                    codec = codec,
                                    level = level.toInt(),
                                    password = pwChars,
                                    pqRecipientPublic = pqPub,
                                    files = fileInputs
                                ),
                                progress = { processed, total, phase ->
                                    val pct = if (total > 0) (processed * 100 / total) else 0
                                    progressText = "$phase… $pct% (${formatSize(processed)})"
                                }
                            )
                        }
                    }
                    lastStats = "${formatSize(result.archiveSize)}  ·  " +
                            "ratio ${"%.2f".format(result.ratio)}  ·  " +
                            "${inputs.size} files  ·  ${result.blockCount} blocks"
                    lastMsg = "Saved ${formatSize(result.archiveSize)}" to GreenOk
                } catch (e: Throwable) {
                    lastMsg = "Error: ${e.message ?: e.javaClass.simpleName}" to RedFail
                } finally {
                    progressText = null
                    running = false
                }
            }
        }
    }

    // ─── UI ─────────────────────────────────────────────────────────────
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionCard(
            title = "Compress & Encrypt",
            subtitle = "Pick multiple files and/or folders. All entries go into one .zupt archive. " +
                    "Streaming compression — memory constant regardless of total size.",
            accent = Cy0
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                PickButton(
                    icon = Icons.Default.Description,
                    label = "Add files",
                    accent = Cy0,
                    modifier = Modifier.weight(1f),
                    onClick = { filesPicker.launch(arrayOf("*/*")) }
                )
                PickButton(
                    icon = Icons.Default.Folder,
                    label = "Add folder",
                    accent = Mg0,
                    modifier = Modifier.weight(1f),
                    onClick = { folderPicker.launch(null) }
                )
            }

            if (inputs.isNotEmpty()) {
                Spacer(Modifier.height(12.dp))
                Text(
                    "${inputs.size} item${if (inputs.size == 1) "" else "s"}  ·  " +
                            formatSize(inputs.sumOf { it.size }),
                    color = Ink2,
                    style = MaterialTheme.typography.labelMedium
                )
                Spacer(Modifier.height(8.dp))
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    for (item in inputs.toList()) {
                        InputRow(
                            path = item.path,
                            size = item.size,
                            onRemove = { inputs.remove(item) }
                        )
                    }
                }
                Spacer(Modifier.height(8.dp))
                TextButton(onClick = { inputs.clear() }) {
                    Icon(Icons.Default.Clear, null, tint = Ink2, modifier = Modifier.size(14.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Clear all", color = Ink2, style = MaterialTheme.typography.labelMedium)
                }
            }
        }

        SectionCard(title = "Codec") {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                CodecId.values().forEach { c ->
                    val selected = codec == c
                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .clip(RoundedCornerShape(10.dp))
                            .background(if (selected) Bg4 else Bg2)
                            .border(1.dp,
                                if (selected) StrokeHot else StrokeWeak,
                                RoundedCornerShape(10.dp))
                            .clickable { codec = c }
                            .padding(vertical = 12.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(c.label, color = if (selected) Cy0 else Ink1,
                            style = MaterialTheme.typography.labelMedium)
                    }
                }
            }
            Spacer(Modifier.height(14.dp))
            Text(
                "LEVEL · ${level.toInt()}".uppercase(),
                color = Ink2, style = MaterialTheme.typography.labelMedium
            )
            Slider(
                value = level,
                onValueChange = { level = it },
                valueRange = 1f..9f,
                steps = 7,
                colors = SliderDefaults.colors(
                    thumbColor = Cy0,
                    activeTrackColor = Cy0,
                    inactiveTrackColor = Bg4
                )
            )
        }

        SectionCard(title = "Encryption", accent = Mg0) {
            PasswordField(password, { password = it }, "Password (optional)")
            Spacer(Modifier.height(14.dp))
            KeyUploadField(
                value = pqPublic,
                onChange = { pqPublic = it; if (pqKeyFilename != null) pqKeyFilename = null },
                label = "PQ Public Key (optional)",
                filename = pqKeyFilename,
                onUploadClick = { keyPicker.launch(arrayOf("*/*")) }
            )
            Spacer(Modifier.height(6.dp))
            Text(
                "If both are set, keys are combined via SHAKE256 — recipient needs both password AND private key.",
                color = Ink2, style = MaterialTheme.typography.bodySmall
            )
        }

        val enabled = inputs.isNotEmpty() && !running
        GlowButton(
            text = if (running) "Processing…" else "Compress & Save",
            enabled = enabled,
            onClick = {
                val base = if (inputs.size == 1) inputs[0].path.substringAfterLast('/')
                           else "archive"
                saver.launch("$base.zupt")
            }
        )

        progressText?.let {
            Text(it, color = Cy0, style = MaterialTheme.typography.bodySmall)
        }
        lastStats?.let {
            Text(it, color = Ink1, style = MaterialTheme.typography.bodySmall)
        }
        lastMsg?.let { (m, c) ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Check, null, tint = c, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(8.dp))
                Text(m, color = c, style = MaterialTheme.typography.bodyMedium)
            }
        }
    }
}

@Composable
private fun PickButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    accent: androidx.compose.ui.graphics.Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    Box(
        modifier = modifier
            .height(80.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(Bg2)
            .dashedBorder(accent.copy(alpha = 0.35f), 14.dp)
            .clickable { onClick() },
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(icon, null, tint = accent, modifier = Modifier.size(22.dp))
            Spacer(Modifier.height(6.dp))
            Text(label.uppercase(), color = accent, style = MaterialTheme.typography.labelMedium)
        }
    }
}

@Composable
private fun InputRow(path: String, size: Long, onRemove: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(Bg2)
            .border(1.dp, StrokeWeak, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = if (path.contains('/')) Icons.Default.InsertDriveFile else Icons.Default.Description,
            contentDescription = null,
            tint = Ink2,
            modifier = Modifier.size(14.dp)
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Text(path, color = Ink0, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            Text(formatSize(size), color = Ink2, style = MaterialTheme.typography.bodySmall)
        }
        Icon(
            Icons.Default.Close, null, tint = RedFail,
            modifier = Modifier.size(18.dp).clickable { onRemove() }
        )
    }
}

/** Recursively walk a DocumentFile tree, invoking cb on each file with virtual path. */
private fun walkTree(
    root: DocumentFile, rootName: String,
    cb: (DocumentFile, String) -> Unit
) {
    fun recurse(d: DocumentFile, prefix: String) {
        for (child in d.listFiles()) {
            val name = child.name ?: continue
            val virtualPath = "$prefix/$name"
            if (child.isDirectory) recurse(child, virtualPath)
            else if (child.isFile) cb(child, virtualPath)
        }
    }
    recurse(root, rootName)
}
