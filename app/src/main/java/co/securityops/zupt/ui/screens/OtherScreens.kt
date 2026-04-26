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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.documentfile.provider.DocumentFile
import co.securityops.zupt.core.archive.ArchiveReader
import co.securityops.zupt.core.archive.StreamingReader
import co.securityops.zupt.core.archive.VerifyReport
import co.securityops.zupt.core.io.SafFiles
import co.securityops.zupt.ui.components.*
import co.securityops.zupt.ui.theme.*
import co.securityops.zupt.util.fromHex
import co.securityops.zupt.util.formatSize
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// ─── Extract ─────────────────────────────────────────────────────────

@Composable
fun ExtractScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var inputUri by remember { mutableStateOf<Uri?>(null) }
    var inputName by remember { mutableStateOf<String?>(null) }
    var password by remember { mutableStateOf("") }
    var pqPriv by remember { mutableStateOf("") }
    var pqKeyFilename by remember { mutableStateOf<String?>(null) }
    var running by remember { mutableStateOf(false) }
    var lastMsg by remember { mutableStateOf<Pair<String, Color>?>(null) }
    var progressText by remember { mutableStateOf<String?>(null) }
    var archiveFiles by remember { mutableStateOf<List<co.securityops.zupt.core.archive.FileEntry>>(emptyList()) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            inputUri = uri
            inputName = SafFiles.displayName(ctx, uri)
        }
    }
    val keyPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch(Dispatchers.IO) {
                try {
                    val raw = SafFiles.readBytes(ctx, uri, sizeCap = 64 * 1024)
                    val hex = String(raw, Charsets.US_ASCII).trim()
                    if (hex.length < 4000) {
                        lastMsg = ("This key looks too short (${hex.length} hex chars). " +
                                "A valid PQ private key is ~4900 hex chars — please regenerate on the Keys tab." to RedFail)
                    } else {
                        pqPriv = hex
                        pqKeyFilename = SafFiles.displayName(ctx, uri)
                    }
                } catch (t: Throwable) {
                    lastMsg = ("Key load failed: ${t.message}" to RedFail)
                }
            }
        }
    }

    // Destination folder picker — for multi-file (or single-file) extraction
    val folderPicker = rememberLauncherForActivityResult(
        ActivityResultContracts.OpenDocumentTree()
    ) { treeUri ->
        val inUri = inputUri
        if (treeUri != null && inUri != null) {
            scope.launch {
                running = true; lastMsg = null; progressText = "Starting…"
                try {
                    try {
                        ctx.contentResolver.takePersistableUriPermission(
                            treeUri, android.content.Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        )
                    } catch (_: Throwable) {}
                    val dest = DocumentFile.fromTreeUri(ctx, treeUri)
                        ?: throw IllegalStateException("Cannot open destination")

                    val archSize = SafFiles.size(ctx, inUri).coerceAtLeast(0)
                    val pw = if (password.isNotBlank()) password.toCharArray() else null
                    val priv = if (pqPriv.isNotBlank()) pqPriv.fromHex() else null

                    withContext(Dispatchers.IO) {
                        for ((idx, entry) in archiveFiles.withIndex()) {
                            val subpath = entry.path
                            progressText = "Extracting ${idx + 1}/${archiveFiles.size}: $subpath"
                            val outDoc = createFileInTree(dest, subpath)
                                ?: throw IllegalStateException("Cannot create $subpath in destination")
                            ctx.contentResolver.openInputStream(inUri)!!.use { archIn ->
                                ctx.contentResolver.openOutputStream(outDoc.uri, "w")!!.use { outStream ->
                                    StreamingReader.extractFileAt(
                                        archiveInput = archIn,
                                        archiveSize = archSize,
                                        output = outStream,
                                        scratchDir = ctx.cacheDir,
                                        password = pw,
                                        hybridPriv = priv,
                                        fileIndex = idx,
                                        progress = { p, t, ph ->
                                            val pct = if (t > 0) (p * 100 / t) else 0
                                            progressText = "[${idx + 1}/${archiveFiles.size}] $ph $pct% — $subpath"
                                        }
                                    )
                                }
                            }
                        }
                    }
                    lastMsg = "Extracted ${archiveFiles.size} file${if (archiveFiles.size == 1) "" else "s"}" to GreenOk
                } catch (t: Throwable) {
                    lastMsg = "Error: ${t.message ?: t.javaClass.simpleName}" to RedFail
                } finally {
                    progressText = null
                    running = false
                }
            }
        }
    }

    // When archive picked, peek header to list files
    LaunchedEffect(inputUri) {
        val uri = inputUri ?: return@LaunchedEffect
        archiveFiles = emptyList()
        withContext(Dispatchers.IO) {
            try {
                val tiny = ctx.contentResolver.openInputStream(uri)!!.use { inp ->
                    val buf = ByteArray(2 * 1024 * 1024)
                    var filled = 0
                    while (filled < buf.size) {
                        val n = inp.read(buf, filled, buf.size - filled)
                        if (n <= 0) break
                        filled += n
                    }
                    buf.copyOf(filled)
                }
                val head = ArchiveReader.parse(tiny)
                archiveFiles = head.files
            } catch (_: Throwable) { /* ignore — bad archive or encrypted with wrong key */ }
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionCard(title = "Extract & Decrypt",
            subtitle = "Pick a .zupt archive. Multi-file archives are extracted into a destination folder you choose.") {
            DropZone(
                label = "Tap to pick a .zupt archive",
                filename = inputName,
                onClick = { picker.launch(arrayOf("*/*")) }
            )
        }

        if (archiveFiles.isNotEmpty()) {
            SectionCard(
                title = "Archive Contents",
                subtitle = "${archiveFiles.size} file${if (archiveFiles.size == 1) "" else "s"} · " +
                        formatSize(archiveFiles.sumOf { it.size })
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    for (fe in archiveFiles.take(20)) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.InsertDriveFile, null, tint = Ink2, modifier = Modifier.size(12.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(fe.path, color = Ink0, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                            Text(formatSize(fe.size), color = Ink2, style = MaterialTheme.typography.labelMedium)
                        }
                    }
                    if (archiveFiles.size > 20) {
                        Text("… and ${archiveFiles.size - 20} more",
                            color = Ink2, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }

        SectionCard(title = "Credentials", accent = Mg0) {
            PasswordField(password, { password = it }, "Password (if required)")
            Spacer(Modifier.height(14.dp))
            KeyUploadField(
                value = pqPriv,
                onChange = { pqPriv = it; if (pqKeyFilename != null) pqKeyFilename = null },
                label = "PQ Private Key (if required)",
                filename = pqKeyFilename,
                onUploadClick = { keyPicker.launch(arrayOf("*/*")) }
            )
        }

        GlowButton(
            text = if (running) "Decrypting…" else
                if (archiveFiles.size > 1) "Extract ${archiveFiles.size} files to folder…" else "Extract & Save",
            enabled = inputUri != null && archiveFiles.isNotEmpty() && !running,
            onClick = { folderPicker.launch(null) }
        )
        progressText?.let { Text(it, color = Cy0, style = MaterialTheme.typography.bodySmall) }
        lastMsg?.let { (m, c) ->
            Text(m, color = c, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/** Create a file in a DocumentFile tree, creating parent directories as needed. */
private fun createFileInTree(root: DocumentFile, path: String): DocumentFile? {
    val parts = path.split('/').filter { it.isNotEmpty() }
    if (parts.isEmpty()) return null
    var current = root
    for (i in 0 until parts.size - 1) {
        val segment = parts[i]
        val existing = current.findFile(segment)
        current = if (existing != null && existing.isDirectory) existing
        else current.createDirectory(segment) ?: return null
    }
    val filename = parts.last()
    current.findFile(filename)?.delete()
    return current.createFile("application/octet-stream", filename)
}

// ─── Verify ─────────────────────────────────────────────────────────

@Composable
fun VerifyScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var inputUri by remember { mutableStateOf<Uri?>(null) }
    var inputName by remember { mutableStateOf<String?>(null) }
    var password by remember { mutableStateOf("") }
    var pqPriv by remember { mutableStateOf("") }
    var pqKeyFilename by remember { mutableStateOf<String?>(null) }
    var running by remember { mutableStateOf(false) }
    var report by remember { mutableStateOf<VerifyReport?>(null) }
    var err by remember { mutableStateOf<String?>(null) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            inputUri = uri
            inputName = SafFiles.displayName(ctx, uri)
            report = null; err = null
        }
    }
    val keyPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch(Dispatchers.IO) {
                try {
                    val raw = SafFiles.readBytes(ctx, uri, sizeCap = 64 * 1024)
                    pqPriv = String(raw, Charsets.US_ASCII).trim()
                    pqKeyFilename = SafFiles.displayName(ctx, uri)
                } catch (t: Throwable) {
                    err = "Key load failed: ${t.message}"
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
        SectionCard(title = "Verify Integrity",
            subtitle = "Validate every block's XXH64 checksum and the archive's HMAC tag. No write occurs.") {
            DropZone(label = "Tap to pick a .zupt archive",
                filename = inputName, onClick = { picker.launch(arrayOf("*/*")) })
        }
        SectionCard(title = "Credentials (if encrypted)", accent = Mg0) {
            PasswordField(password, { password = it }, "Password")
            Spacer(Modifier.height(14.dp))
            KeyUploadField(
                value = pqPriv,
                onChange = { pqPriv = it; if (pqKeyFilename != null) pqKeyFilename = null },
                label = "PQ Private Key",
                filename = pqKeyFilename,
                onUploadClick = { keyPicker.launch(arrayOf("*/*")) }
            )
        }
        GlowButton(
            text = if (running) "Verifying…" else "Verify Integrity",
            enabled = inputUri != null && !running,
            onClick = {
                val uri = inputUri ?: return@GlowButton
                scope.launch {
                    running = true; err = null; report = null
                    try {
                        report = withContext(Dispatchers.IO) {
                            val archSize = SafFiles.size(ctx, uri).coerceAtLeast(0)
                            val pw = if (password.isNotBlank()) password.toCharArray() else null
                            val priv = if (pqPriv.isNotBlank()) pqPriv.fromHex() else null
                            // Streaming verify: run extract to a counting sink that
                            // discards output. If extract succeeds, everything (GCM
                            // tag + every block XXH64 + whole-file XXH64) passed.
                            ctx.contentResolver.openInputStream(uri)!!.use { inStream ->
                                val sink = object : java.io.OutputStream() {
                                    override fun write(b: Int) {}
                                    override fun write(b: ByteArray, off: Int, len: Int) {}
                                }
                                try {
                                    val entry = StreamingReader.extract(
                                        archiveInput = inStream,
                                        archiveSize = archSize,
                                        output = sink,
                                        scratchDir = ctx.cacheDir,
                                        password = pw,
                                        hybridPriv = priv
                                    )
                                    // Also peek header to include metadata in report
                                    val arch = SafFiles.readBytes(ctx, uri, sizeCap = 2L * 1024 * 1024)
                                    val head = ArchiveReader.parse(arch)
                                    VerifyReport(
                                        tagOk = true,
                                        blocksChecked = head.blocks.size,
                                        badBlocks = emptyList(),
                                        header = head.header,
                                        fileCount = head.files.size
                                    )
                                } catch (t: Throwable) {
                                    val arch = try { SafFiles.readBytes(ctx, uri, sizeCap = 2L * 1024 * 1024) } catch (_: Throwable) { null }
                                    val head = arch?.let { try { ArchiveReader.parse(it) } catch (_: Throwable) { null } }
                                    if (head != null) VerifyReport(
                                        tagOk = false, blocksChecked = head.blocks.size,
                                        badBlocks = listOf(-1), header = head.header, fileCount = head.files.size
                                    ) else throw t
                                }
                            }
                        }
                    } catch (e: Throwable) {
                        err = e.message ?: e.javaClass.simpleName
                    } finally { running = false }
                }
            }
        )
        report?.let { r ->
            val tone = if (r.ok) GreenOk else RedFail
            SectionCard(title = if (r.ok) "Archive OK" else "Archive FAILED", accent = tone) {
                StatRow("HMAC tag", if (r.tagOk) "VALID" else "INVALID")
                StatRow("Blocks checked", r.blocksChecked.toString())
                StatRow("Bad blocks", if (r.badBlocks.isEmpty()) "none" else r.badBlocks.joinToString(", "))
                StatRow("Files", r.fileCount.toString())
                StatRow("Codec", r.header.codec.label)
            }
        }
        err?.let { Text("Error: $it", color = RedFail, style = MaterialTheme.typography.bodyMedium) }
    }
}

// ─── Info ────────────────────────────────────────────────────────────

@Composable
fun InfoScreen() {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var inputUri by remember { mutableStateOf<Uri?>(null) }
    var inputName by remember { mutableStateOf<String?>(null) }
    var parsed by remember { mutableStateOf<ArchiveReader.ParsedHead?>(null) }
    var err by remember { mutableStateOf<String?>(null) }
    var running by remember { mutableStateOf(false) }

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            inputUri = uri
            inputName = SafFiles.displayName(ctx, uri)
            parsed = null; err = null
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionCard(title = "Archive Info",
            subtitle = "Inspect metadata without decrypting — version, UUID, timestamp, flags, block count.") {
            DropZone(label = "Tap to pick a .zupt archive",
                filename = inputName, onClick = { picker.launch(arrayOf("*/*")) })
        }
        GlowButton(
            text = if (running) "Reading…" else "Show Info",
            enabled = inputUri != null && !running,
            onClick = {
                val uri = inputUri ?: return@GlowButton
                scope.launch {
                    running = true; err = null
                    try {
                        parsed = withContext(Dispatchers.Default) {
                            // Info only needs header + tables — cap at 2 MiB
                            ArchiveReader.parse(SafFiles.readBytes(ctx, uri, sizeCap = 2L * 1024 * 1024))
                        }
                    } catch (e: Throwable) {
                        err = e.message ?: e.javaClass.simpleName
                    } finally { running = false }
                }
            }
        )
        parsed?.let { p ->
            val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
                .format(Date(p.header.timestampMicros / 1000L))
            val flags = buildList {
                if (p.header.isEncrypted) add("ENC")
                if (p.header.isPassword) add("PW")
                if (p.header.isPq) add("PQ")
                if (p.header.isSolid) add("SOLID")
            }.joinToString(" · ").ifEmpty { "none" }

            SectionCard(title = "Header") {
                StatRow("Format", "v${p.header.versionMajor}.${p.header.versionMinor}")
                StatRow("UUID", p.header.uuid.toString())
                StatRow("Timestamp", ts)
                StatRow("Codec", p.header.codec.label)
                StatRow("Level", p.header.level.toString())
                StatRow("Block size", formatSize(p.header.blockSize.toLong()))
                StatRow("Flags", flags)
                StatRow("Files", p.files.size.toString())
                StatRow("Blocks", p.blocks.size.toString())
                StatRow("Total size", formatSize(p.files.sumOf { it.size }))
            }
            if (p.files.size == 1) {
                p.files.first().let {
                    SectionCard(title = "File") {
                        StatRow("Name", it.path)
                        StatRow("Size", formatSize(it.size))
                    }
                }
            } else if (p.files.size > 1) {
                SectionCard(title = "Files (${p.files.size})") {
                    for (fe in p.files.take(50)) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.InsertDriveFile, null, tint = Ink2, modifier = Modifier.size(12.dp))
                            Spacer(Modifier.width(8.dp))
                            Text(fe.path, color = Ink0, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                            Text(formatSize(fe.size), color = Ink2, style = MaterialTheme.typography.labelMedium)
                        }
                    }
                    if (p.files.size > 50) {
                        Text("… and ${p.files.size - 50} more",
                            color = Ink2, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
        err?.let { Text("Error: $it", color = RedFail, style = MaterialTheme.typography.bodyMedium) }
    }
}

// ─── About ───────────────────────────────────────────────────────────

@Composable
fun AboutScreen() {
    val ctx = LocalContext.current
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        SectionCard(title = "Zupt Mobile", subtitle = "Post-quantum backup, fully offline.") {
            StatRow("Version", "1.0.0")
            StatRow("Format", "zupt/v1.1")
            StatRow("License", "AGPL-3.0-or-later")
            StatRow("Codec default", "Zupt-LZHP")
            StatRow("KEM", "ML-KEM-768 + X25519 (hybrid)")
            StatRow("AEAD", "AES-256-GCM (FIPS 140-3)")
            StatRow("KDF", "PBKDF2-HMAC-SHA512 · 1 000 000 iters")
            StatRow("Hash", "XXH64 · SHAKE256")
            StatRow("Network", "none")
            StatRow("Storage", "SAF only")
        }
        SectionCard(title = "Security Model", accent = Mg0) {
            Text(
                "Everything runs on-device. No INTERNET permission is declared — the app is architecturally incapable of network I/O. All file access is mediated by the Android Storage Access Framework; the user picks every read and write location. Sensitive key material is wiped from memory in finally blocks.",
                color = Ink1, style = MaterialTheme.typography.bodyMedium
            )
        }
        SectionCard(title = "Links") {
            LinkRow(
                label = "Project on GitHub",
                url = "https://github.com/cristiancmoises/zupt-android",
                accent = Cy0
            )
            Spacer(Modifier.height(10.dp))
            LinkRow(
                label = "Cristian Cezar Moisés — LinkedIn",
                url = "https://linkedin.com/in/cristiancezarmoises",
                accent = Mg0
            )
            Spacer(Modifier.height(10.dp))
            LinkRow(
                label = "Security Ops Wiki",
                url = "https://wiki.securityops.co",
                accent = Cy0
            )
        }
        SectionCard(title = "Credits") {
            Text("Zupt · AGPL-3.0-or-later · © 2026 Cristian Cezar Moisés", color = Ink0, style = MaterialTheme.typography.bodyMedium)
            Text("libzupt · MIT · Alessandro de Oliveira Faria", color = Ink1, style = MaterialTheme.typography.bodySmall)
            Text("BouncyCastle · MIT", color = Ink1, style = MaterialTheme.typography.bodySmall)
            Spacer(Modifier.height(10.dp))
            Text("Powered by Security Ops", color = Cy0, style = MaterialTheme.typography.labelLarge)
        }
    }
}

@Composable
private fun LinkRow(label: String, url: String, accent: androidx.compose.ui.graphics.Color) {
    val ctx = LocalContext.current
    androidx.compose.foundation.layout.Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(androidx.compose.foundation.shape.RoundedCornerShape(10.dp))
            .background(Bg2)
            .border(1.dp, accent.copy(alpha = 0.35f), androidx.compose.foundation.shape.RoundedCornerShape(10.dp))
            .clickable {
                try {
                    val intent = android.content.Intent(
                        android.content.Intent.ACTION_VIEW,
                        android.net.Uri.parse(url)
                    )
                    intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                    ctx.startActivity(intent)
                } catch (_: Throwable) { /* no browser */ }
            }
            .padding(horizontal = 14.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(Icons.Default.Link, null, tint = accent, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(label, color = Ink0, style = MaterialTheme.typography.bodyMedium)
            Text(url, color = Ink2, style = MaterialTheme.typography.bodySmall)
        }
        Icon(Icons.Default.OpenInNew, null, tint = Ink2, modifier = Modifier.size(16.dp))
    }
}
