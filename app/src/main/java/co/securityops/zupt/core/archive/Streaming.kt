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

package co.securityops.zupt.core.archive

import co.securityops.zupt.core.codec.CodecId
import co.securityops.zupt.core.codec.Codecs
import co.securityops.zupt.core.crypto.Aead
import co.securityops.zupt.core.crypto.HybridKem
import co.securityops.zupt.core.crypto.Kdf
import co.securityops.zupt.core.crypto.Xxh64
import co.securityops.zupt.core.crypto.secureRandomBytes
import co.securityops.zupt.core.crypto.wipe
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Streaming archive writer. Memory use is O(blockSize) = 1 MiB by default,
 * independent of input file size. Input can be arbitrarily large.
 *
 * Writes use a two-pass approach:
 *   Pass 1: read input stream block-by-block, compress each block, xxh64 each block,
 *           write each compressed block to a temp file (scratch). Collect block table
 *           entries in memory (16 bytes per block — a 16 GB file with 1 MiB blocks
 *           produces 16384 entries = 256 KB of in-memory table, fine).
 *   Pass 2: write header + block table to output, then stream temp → GCM cipher → output.
 *           For encrypted archives, GCM is fed in chunks via Cipher.update; final tag
 *           is emitted by doFinal. AAD binds the entire pre-payload.
 *
 * Progress callback invoked with (bytes processed, total bytes) periodically.
 */
object StreamingWriter {

    data class Options(
        val codec: CodecId = CodecId.DEFLATE,
        val level: Int = 6,
        val password: CharArray? = null,
        val pqRecipientPublic: ByteArray? = null,
        val blockLog2: Int = Format.DEFAULT_BLOCK_LOG2,
        val fileName: String,
        val fileSize: Long,
        val fileMtimeMicros: Long = System.currentTimeMillis() * 1000L,
        val fileMode: Int = 0b110_100_100
    )

    /**
     * One file in a multi-file archive. The provider is called at pass-1 time to
     * obtain a fresh InputStream (so the caller can open SAF URIs lazily and
     * avoid holding many file descriptors open simultaneously).
     */
    data class FileInput(
        val path: String,
        val size: Long,
        val openStream: () -> InputStream,
        val mtimeMicros: Long = System.currentTimeMillis() * 1000L,
        val mode: Int = 0b110_100_100
    )

    data class MultiOptions(
        val codec: CodecId = CodecId.DEFLATE,
        val level: Int = 6,
        val password: CharArray? = null,
        val pqRecipientPublic: ByteArray? = null,
        val blockLog2: Int = Format.DEFAULT_BLOCK_LOG2,
        val files: List<FileInput>
    ) {
        val totalSize: Long get() = files.sumOf { it.size }
    }

    data class Result(
        val archiveSize: Long,
        val blockCount: Int,
        val ratio: Double
    )

    fun interface ProgressCallback {
        fun onProgress(processedBytes: Long, totalBytes: Long, phase: String)
    }

    /**
     * @param input input stream of the file to compress
     * @param output output stream of the archive to produce
     * @param scratchDir directory where we can write temporary files (app cache)
     */
    fun write(
        input: InputStream,
        output: OutputStream,
        scratchDir: File,
        opts: Options,
        progress: ProgressCallback = ProgressCallback { _, _, _ -> }
    ): Result {
        val codec = Codecs.byId(opts.codec)
        val blockSize = 1 shl opts.blockLog2
        require(scratchDir.isDirectory || scratchDir.mkdirs()) { "Cannot create scratch dir" }

        // ─── Pass 1: scan input, compress blocks, write to scratch ────────
        val scratch = File.createTempFile("zupt-scratch-", ".bin", scratchDir).apply { deleteOnExit() }
        val blockTable = ArrayList<BlockEntry>(((opts.fileSize + blockSize - 1) / blockSize).toInt().coerceAtLeast(1))
        val fileXxh = Xxh64()
        var totalRead = 0L
        try {
            scratch.outputStream().buffered(256 * 1024).use { scratchOut ->
                val buf = ByteArray(blockSize)
                while (true) {
                    // Read one full block (or less at EOF)
                    var filled = 0
                    while (filled < blockSize) {
                        val n = input.read(buf, filled, blockSize - filled)
                        if (n <= 0) break
                        filled += n
                    }
                    if (filled == 0) break
                    val raw = if (filled == blockSize) buf else buf.copyOfRange(0, filled)

                    val xxh = Xxh64.hash(raw)
                    fileXxh.update(raw, 0, raw.size)

                    val comp = codec.compress(raw, opts.level)
                    val store = if (comp.size < raw.size) comp else raw
                    scratchOut.write(store)
                    blockTable += BlockEntry(raw.size, store.size, xxh)

                    totalRead += filled
                    progress.onProgress(totalRead, opts.fileSize, "Compressing")
                    if (filled < blockSize) break
                }
            }

            // ─── Build header + pre-payload ────────────────────────────────
            var flags = 0
            val needsEnc = opts.password != null || opts.pqRecipientPublic != null
            if (needsEnc) flags = flags or Format.FLAG_ENCRYPTED
            if (opts.password != null) flags = flags or Format.FLAG_PASSWORD
            if (opts.pqRecipientPublic != null) flags = flags or Format.FLAG_PQ

            val header = ArchiveHeader(
                versionMajor = Format.VERSION_MAJOR,
                versionMinor = Format.VERSION_MINOR,
                flags = flags,
                uuid = UUID.randomUUID(),
                timestampMicros = System.currentTimeMillis() * 1000L,
                codec = opts.codec,
                level = opts.level.toByte(),
                blockLog2 = opts.blockLog2.toByte()
            )

            val pre = ByteArrayOutputStream(256 + blockTable.size * 16)
            val dPre = DataOutputStream(pre)
            header.write(dPre)

            var pwKey: ByteArray? = null
            var pqKey: ByteArray? = null
            if (opts.password != null) {
                val salt = secureRandomBytes(32)
                val iters = Kdf.DEFAULT_ITERS
                dPre.write(salt); dPre.writeInt(iters)
                pwKey = Kdf.derive(opts.password, salt, iters)
            }
            if (opts.pqRecipientPublic != null) {
                val encap = HybridKem.encapsulate(opts.pqRecipientPublic)
                dPre.write(encap.ciphertext)
                pqKey = encap.sharedSecret
            }

            // File table (one entry)
            dPre.writeInt(1)
            FileEntry(opts.fileName, opts.fileSize, opts.fileMtimeMicros, opts.fileMode, fileXxh.digest())
                .write(dPre)

            // Block table
            dPre.writeInt(blockTable.size)
            for (be in blockTable) be.write(dPre)

            val preBytes = pre.toByteArray()

            // ─── Pass 2: write pre + payload (encrypted or not) to output ─
            val finalKey = combineKeys(pwKey, pqKey)
            val bufOut = output.buffered(256 * 1024)
            bufOut.write(preBytes)
            var bytesWritten = preBytes.size.toLong()

            if (finalKey != null) {
                val encKey = Aead.deriveEncKey(finalKey)
                val nonce = secureRandomBytes(Aead.NONCE_SIZE)
                bufOut.write(nonce)
                bytesWritten += nonce.size

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encKey, "AES"),
                            GCMParameterSpec(Aead.TAG_BITS, nonce))
                cipher.updateAAD(preBytes)
                cipher.updateAAD(nonce)

                // Stream scratch through cipher to output
                val readBuf = ByteArray(64 * 1024)
                val encBuf = ByteArray(readBuf.size + 32)
                var processed = 0L
                val totalPayload = scratch.length()
                scratch.inputStream().buffered(256 * 1024).use { scratchIn ->
                    while (true) {
                        val n = scratchIn.read(readBuf)
                        if (n <= 0) break
                        val out = cipher.update(readBuf, 0, n, encBuf, 0)
                        if (out > 0) { bufOut.write(encBuf, 0, out); bytesWritten += out }
                        processed += n
                        progress.onProgress(processed, totalPayload, "Encrypting")
                    }
                }
                val finalOut = cipher.doFinal()
                bufOut.write(finalOut)
                bytesWritten += finalOut.size

                encKey.wipe()
                finalKey.wipe()
            } else {
                // Unencrypted: stream scratch → output, append zero-key HMAC
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
                mac.update(preBytes)

                val readBuf = ByteArray(64 * 1024)
                var processed = 0L
                val totalPayload = scratch.length()
                scratch.inputStream().buffered(256 * 1024).use { scratchIn ->
                    while (true) {
                        val n = scratchIn.read(readBuf)
                        if (n <= 0) break
                        bufOut.write(readBuf, 0, n)
                        mac.update(readBuf, 0, n)
                        bytesWritten += n
                        processed += n
                        progress.onProgress(processed, totalPayload, "Writing")
                    }
                }
                val tag = mac.doFinal()
                bufOut.write(tag)
                bytesWritten += tag.size
            }
            bufOut.flush()

            pwKey?.wipe()
            pqKey?.wipe()

            val ratio = if (opts.fileSize > 0) bytesWritten.toDouble() / opts.fileSize.toDouble() else 1.0
            return Result(bytesWritten, blockTable.size, ratio)
        } finally {
            scratch.delete()
        }
    }

    /**
     * Multi-file streaming writer. Each file is compressed into the scratch stream
     * sequentially; the block table records where each file's blocks begin and how
     * many blocks it spans (FileEntry.blockStartIndex / blockCount).
     *
     * Memory: O(blockSize) + O(file_count * 32 bytes for metadata + block table).
     * Disk: scratch is sized to total compressed payload.
     */
    fun writeMulti(
        output: OutputStream,
        scratchDir: File,
        opts: MultiOptions,
        progress: ProgressCallback = ProgressCallback { _, _, _ -> }
    ): Result {
        require(opts.files.isNotEmpty()) { "No files to compress" }
        val codec = Codecs.byId(opts.codec)
        val blockSize = 1 shl opts.blockLog2
        require(scratchDir.isDirectory || scratchDir.mkdirs()) { "Cannot create scratch dir" }

        val scratch = File.createTempFile("zupt-multi-", ".bin", scratchDir).apply { deleteOnExit() }
        val blockTable = ArrayList<BlockEntry>(256)
        val fileEntries = ArrayList<FileEntry>(opts.files.size)
        val totalSize = opts.totalSize
        var totalProcessedAcrossFiles = 0L

        try {
            scratch.outputStream().buffered(256 * 1024).use { scratchOut ->
                for (fileInput in opts.files) {
                    val startBlockIdx = blockTable.size
                    val fileXxh = Xxh64()
                    var fileBytesRead = 0L

                    fileInput.openStream().use { inStream ->
                        val buf = ByteArray(blockSize)
                        while (true) {
                            var filled = 0
                            while (filled < blockSize) {
                                val n = inStream.read(buf, filled, blockSize - filled)
                                if (n <= 0) break
                                filled += n
                            }
                            if (filled == 0) break
                            val raw = if (filled == blockSize) buf else buf.copyOfRange(0, filled)

                            val xxh = Xxh64.hash(raw)
                            fileXxh.update(raw, 0, raw.size)
                            fileBytesRead += filled

                            val comp = codec.compress(raw, opts.level)
                            val store = if (comp.size < raw.size) comp else raw
                            scratchOut.write(store)
                            blockTable += BlockEntry(raw.size, store.size, xxh)

                            totalProcessedAcrossFiles += filled
                            progress.onProgress(
                                totalProcessedAcrossFiles, totalSize,
                                "Compressing ${fileInput.path}"
                            )
                            if (filled < blockSize) break
                        }
                    }

                    val blocksUsed = blockTable.size - startBlockIdx
                    fileEntries += FileEntry(
                        path = fileInput.path,
                        size = fileBytesRead,
                        mtimeMicros = fileInput.mtimeMicros,
                        mode = fileInput.mode,
                        xxh64 = fileXxh.digest(),
                        blockStartIndex = startBlockIdx,
                        blockCount = blocksUsed
                    )
                }
            }

            // ─── Build header ──────────────────────────────────────────────
            var flags = 0
            val needsEnc = opts.password != null || opts.pqRecipientPublic != null
            if (needsEnc) flags = flags or Format.FLAG_ENCRYPTED
            if (opts.password != null) flags = flags or Format.FLAG_PASSWORD
            if (opts.pqRecipientPublic != null) flags = flags or Format.FLAG_PQ

            val header = ArchiveHeader(
                versionMajor = Format.VERSION_MAJOR,
                versionMinor = Format.VERSION_MINOR,
                flags = flags,
                uuid = UUID.randomUUID(),
                timestampMicros = System.currentTimeMillis() * 1000L,
                codec = opts.codec,
                level = opts.level.toByte(),
                blockLog2 = opts.blockLog2.toByte()
            )

            val pre = ByteArrayOutputStream(2048 + blockTable.size * 16)
            val dPre = DataOutputStream(pre)
            header.write(dPre)

            var pwKey: ByteArray? = null
            var pqKey: ByteArray? = null
            if (opts.password != null) {
                val salt = secureRandomBytes(32)
                val iters = Kdf.DEFAULT_ITERS
                dPre.write(salt); dPre.writeInt(iters)
                pwKey = Kdf.derive(opts.password, salt, iters)
            }
            if (opts.pqRecipientPublic != null) {
                val encap = HybridKem.encapsulate(opts.pqRecipientPublic)
                dPre.write(encap.ciphertext)
                pqKey = encap.sharedSecret
            }

            // File table
            dPre.writeInt(fileEntries.size)
            for (fe in fileEntries) fe.write(dPre)
            // Block table
            dPre.writeInt(blockTable.size)
            for (be in blockTable) be.write(dPre)

            val preBytes = pre.toByteArray()

            // ─── Write pre + payload (encrypted or not) to output ──────────
            val finalKey = combineKeys(pwKey, pqKey)
            val bufOut = output.buffered(256 * 1024)
            bufOut.write(preBytes)
            var bytesWritten = preBytes.size.toLong()

            if (finalKey != null) {
                val encKey = Aead.deriveEncKey(finalKey)
                val nonce = secureRandomBytes(Aead.NONCE_SIZE)
                bufOut.write(nonce); bytesWritten += nonce.size

                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encKey, "AES"),
                            GCMParameterSpec(Aead.TAG_BITS, nonce))
                cipher.updateAAD(preBytes); cipher.updateAAD(nonce)

                val readBuf = ByteArray(64 * 1024)
                val encBuf = ByteArray(readBuf.size + 32)
                var processed = 0L
                val totalPayload = scratch.length()
                scratch.inputStream().buffered(256 * 1024).use { scratchIn ->
                    while (true) {
                        val n = scratchIn.read(readBuf); if (n <= 0) break
                        val out = cipher.update(readBuf, 0, n, encBuf, 0)
                        if (out > 0) { bufOut.write(encBuf, 0, out); bytesWritten += out }
                        processed += n
                        progress.onProgress(processed, totalPayload, "Encrypting")
                    }
                }
                val finalOut = cipher.doFinal()
                bufOut.write(finalOut); bytesWritten += finalOut.size
                encKey.wipe(); finalKey.wipe()
            } else {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
                mac.update(preBytes)

                val readBuf = ByteArray(64 * 1024)
                var processed = 0L
                val totalPayload = scratch.length()
                scratch.inputStream().buffered(256 * 1024).use { scratchIn ->
                    while (true) {
                        val n = scratchIn.read(readBuf); if (n <= 0) break
                        bufOut.write(readBuf, 0, n)
                        mac.update(readBuf, 0, n)
                        bytesWritten += n; processed += n
                        progress.onProgress(processed, totalPayload, "Writing")
                    }
                }
                val tag = mac.doFinal(); bufOut.write(tag); bytesWritten += tag.size
            }
            bufOut.flush()

            pwKey?.wipe(); pqKey?.wipe()

            val ratio = if (totalSize > 0) bytesWritten.toDouble() / totalSize.toDouble() else 1.0
            return Result(bytesWritten, blockTable.size, ratio)
        } finally {
            scratch.delete()
        }
    }

    private fun combineKeys(pw: ByteArray?, pq: ByteArray?): ByteArray? {
        if (pw == null && pq == null) return null
        if (pw != null && pq == null) return pw
        if (pw == null && pq != null) return pq
        val shake = org.bouncycastle.crypto.digests.SHAKEDigest(256)
        shake.update(pw!!, 0, pw.size)
        shake.update(pq!!, 0, pq.size)
        val info = "ZUPT-PWPQ-v1".toByteArray(Charsets.US_ASCII)
        shake.update(info, 0, info.size)
        val out = ByteArray(64)
        shake.doFinal(out, 0, 64)
        return out
    }
}

/**
 * Streaming archive reader. Memory use is O(blockSize), independent of archive size.
 *
 * Unlike the writer, the reader must verify the full GCM authentication tag BEFORE
 * trusting any payload byte (standard AEAD contract). We therefore:
 *   1. Parse header + block table (small, always fits in memory)
 *   2. Stream ciphertext through GCM decrypt into a scratch file
 *   3. If GCM tag verifies, stream scratch → decompress → output
 *   4. Delete scratch
 *
 * This leaks encryption artifacts (the scratch file) to disk briefly. We mitigate
 * by writing to app-private cache dir and wiping before delete.
 */
object StreamingReader {

    fun interface ProgressCallback {
        fun onProgress(processedBytes: Long, totalBytes: Long, phase: String)
    }

    /**
     * Read the header-only section of an archive (lightweight, in memory).
     */
    fun parseHeader(input: InputStream): Pair<ArchiveReader.ParsedHead, ByteArray> {
        // Read the first 64 KB — more than enough for header + KDF + PQ + reasonable block tables
        // Actually need smart approach: read incrementally until we know full pre-payload size
        val buf = ByteArrayOutputStream()
        val tmp = ByteArray(8192)
        // First, pull enough for header (48 B)
        while (buf.size() < Format.HEADER_SIZE) {
            val n = input.read(tmp, 0, Format.HEADER_SIZE - buf.size())
            if (n <= 0) throw IllegalStateException("Archive truncated in header")
            buf.write(tmp, 0, n)
        }
        // Now we can read the header and know what else to pull
        // Simpler: read enough for any reasonable header+tables (512 KB), fall back to grow
        while (buf.size() < 1024 * 1024) {
            val n = input.read(tmp)
            if (n <= 0) break
            buf.write(tmp, 0, n)
        }
        val bytes = buf.toByteArray()
        return ArchiveReader.parse(bytes) to bytes
    }

    /**
     * Full streaming extract:
     *   archiveInput  — the encrypted archive
     *   archiveSize   — known size of the archive (for progress and seek math)
     *   output        — destination for decrypted, decompressed file
     *   scratchDir    — temp dir for GCM-decrypted intermediate
     */
    fun extract(
        archiveInput: InputStream,
        archiveSize: Long,
        output: OutputStream,
        scratchDir: File,
        password: CharArray?,
        hybridPriv: ByteArray?,
        progress: ProgressCallback = ProgressCallback { _, _, _ -> }
    ): FileEntry = extractFileAt(archiveInput, archiveSize, output, scratchDir, password, hybridPriv, 0, progress)

    /**
     * Extract a specific file by index from a multi-file archive.
     * @param fileIndex 0-based index into head.files list
     */
    fun extractFileAt(
        archiveInput: InputStream,
        archiveSize: Long,
        output: OutputStream,
        scratchDir: File,
        password: CharArray?,
        hybridPriv: ByteArray?,
        fileIndex: Int,
        progress: ProgressCallback = ProgressCallback { _, _, _ -> }
    ): FileEntry {
        require(scratchDir.isDirectory || scratchDir.mkdirs()) { "Cannot create scratch dir" }
        // Stage 1: read the archive into a scratch file. Necessary because GCM
        // requires the ciphertext to be available sequentially and the header
        // is prefix-addressed while the tag is at the end.
        val archiveScratch = File.createTempFile("zupt-in-", ".bin", scratchDir).apply { deleteOnExit() }
        // Stage 2: after the header is parsed, GCM-decrypt the ciphertext into
        // this second scratch, streaming via Cipher.update. Final tag check
        // happens on doFinal — if it fails, this file is zeroed.
        val plainScratch = File.createTempFile("zupt-plain-", ".bin", scratchDir).apply { deleteOnExit() }

        try {
            // ─── Stage 1: archive → archiveScratch ─────────────────────────
            archiveScratch.outputStream().buffered(256 * 1024).use { out ->
                val buf = ByteArray(64 * 1024)
                var total = 0L
                while (true) {
                    val n = archiveInput.read(buf)
                    if (n <= 0) break
                    out.write(buf, 0, n)
                    total += n
                    progress.onProgress(total, archiveSize, "Reading")
                }
            }

            // ─── Parse header (only prefix needed) ─────────────────────────
            val raf = RandomAccessFile(archiveScratch, "r")
            try {
                // Read up to 2 MiB for header + tables; big block tables fit here
                // (2 MiB / 16 B per entry = 131K blocks = 131 GB file @ 1 MiB blocks)
                val headSize = minOf(2L * 1024 * 1024, raf.length()).toInt()
                val headRegion = ByteArray(headSize)
                raf.seek(0); raf.readFully(headRegion)

                // parse() needs enough bytes for header+tables+maybe more; it also
                // reads payloadSize from archive length, which is wrong if we only
                // pass the head region. Work around: parse on a synthesized archive
                // where we pad with zeros to the true length, then ignore the payload
                // fields (we compute them from raf.length()).
                val parseBuf = headRegion.copyOf(minOf(headRegion.size, 1024 * 1024))
                val head = ArchiveReader.parse(parseBuf)
                require(fileIndex in head.files.indices) {
                    "File index $fileIndex out of bounds (archive has ${head.files.size} files)"
                }
                val fileEntry = head.files[fileIndex]

                // Re-compute payload geometry using true archive length
                val trueLen = raf.length()
                val ivStart: Long = if (head.header.isEncrypted) head.payloadStart.toLong() - Aead.NONCE_SIZE else -1L
                val payloadStart: Long = head.payloadStart.toLong()
                val tagStart: Long = if (head.header.isEncrypted) trueLen else trueLen - 32  // GCM inline; unenc uses trailing HMAC
                val payloadSize: Long = tagStart - payloadStart

                val key = deriveKey(head, password, hybridPriv)

                // ─── Stage 2: streaming decrypt → plainScratch ────────────
                if (head.header.isEncrypted) {
                    if (key == null) throw SecurityException("Archive is encrypted but no key material provided")
                    val encKey = Aead.deriveEncKey(key)
                    val nonce = ByteArray(Aead.NONCE_SIZE)
                    raf.seek(ivStart)
                    raf.readFully(nonce)

                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(encKey, "AES"),
                                GCMParameterSpec(Aead.TAG_BITS, nonce))
                    cipher.updateAAD(head.preBytes)
                    cipher.updateAAD(nonce)

                    plainScratch.outputStream().buffered(256 * 1024).use { plainOut ->
                        raf.seek(payloadStart)
                        val readBuf = ByteArray(64 * 1024)
                        val outBuf = ByteArray(readBuf.size + 32)
                        var remaining = payloadSize
                        var processed = 0L
                        while (remaining > 0) {
                            val n = minOf(readBuf.size.toLong(), remaining).toInt()
                            raf.readFully(readBuf, 0, n)
                            val outN = cipher.update(readBuf, 0, n, outBuf, 0)
                            if (outN > 0) plainOut.write(outBuf, 0, outN)
                            remaining -= n
                            processed += n
                            progress.onProgress(processed, payloadSize, "Decrypting")
                        }
                        try {
                            val finalOut = cipher.doFinal()
                            plainOut.write(finalOut)
                        } catch (t: javax.crypto.AEADBadTagException) {
                            val hint = buildString {
                                append("Authentication failed. ")
                                when {
                                    head.header.isPassword && head.header.isPq ->
                                        append("Archive needs BOTH password AND PQ private key.")
                                    head.header.isPassword -> append("Check the password.")
                                    head.header.isPq ->
                                        append("PQ private key does not match the public key used to encrypt.")
                                    else -> append("Archive appears tampered.")
                                }
                            }
                            throw SecurityException(hint, t)
                        }
                    }
                    encKey.wipe()
                    key.wipe()
                } else {
                    // Unencrypted: just copy the payload region
                    plainScratch.outputStream().buffered(256 * 1024).use { plainOut ->
                        raf.seek(payloadStart)
                        val buf = ByteArray(64 * 1024)
                        var remaining = payloadSize
                        while (remaining > 0) {
                            val n = minOf(buf.size.toLong(), remaining).toInt()
                            raf.readFully(buf, 0, n)
                            plainOut.write(buf, 0, n)
                            remaining -= n
                        }
                    }
                }

                // ─── Stage 3: plainScratch → codec.decompress → output ─────
                // Use the fileEntry captured above — slice its block range
                val codec = Codecs.byId(head.header.codec)
                // Determine which blocks belong to THIS file (back-compat: blockCount=-1 = all)
                val startIdx = fileEntry.blockStartIndex
                val endIdxEx = if (fileEntry.blockCount < 0) head.blocks.size
                               else startIdx + fileEntry.blockCount
                val fileVerify = Xxh64()
                var writtenTotal = 0L

                // Skip to file's start block in plainScratch
                plainScratch.inputStream().buffered(256 * 1024).use { plainIn ->
                    var skipBytes = 0L
                    for (i in 0 until startIdx) skipBytes += head.blocks[i].compSize
                    var skipped = 0L
                    val skipBuf = ByteArray(64 * 1024)
                    while (skipped < skipBytes) {
                        val n = plainIn.read(skipBuf, 0,
                            minOf(skipBuf.size.toLong(), skipBytes - skipped).toInt())
                        if (n <= 0) throw SecurityException("Payload truncated while seeking to file")
                        skipped += n
                    }

                    output.buffered(256 * 1024).use { outBuf ->
                        for (i in startIdx until endIdxEx) {
                            val be = head.blocks[i]
                            val comp = ByteArray(be.compSize)
                            var read = 0
                            while (read < be.compSize) {
                                val n = plainIn.read(comp, read, be.compSize - read)
                                if (n <= 0) throw SecurityException("Payload truncated at block $i")
                                read += n
                            }
                            val raw = try {
                                if (be.compSize == be.rawSize) comp
                                else codec.decompress(comp, be.rawSize)
                            } catch (t: Throwable) {
                                throw SecurityException("Block $i decompress failed: ${t.message}", t)
                            }
                            if (Xxh64.hash(raw) != be.xxh64)
                                throw SecurityException("Block $i XXH64 mismatch")
                            outBuf.write(raw)
                            fileVerify.update(raw, 0, raw.size)
                            writtenTotal += raw.size
                            progress.onProgress(writtenTotal, fileEntry.size, "Writing")
                        }
                    }
                }
                if (fileVerify.digest() != fileEntry.xxh64)
                    throw SecurityException("Whole-file XXH64 mismatch — data corruption")
                return fileEntry
            } finally {
                raf.close()
            }
        } finally {
            // Best-effort wipe both scratch files before delete (defense in depth)
            for (f in listOf(plainScratch, archiveScratch)) {
                try {
                    if (f.exists()) {
                        RandomAccessFile(f, "rw").use { rw ->
                            val zero = ByteArray(64 * 1024)
                            rw.seek(0)
                            var remaining = rw.length()
                            while (remaining > 0) {
                                val n = minOf(zero.size.toLong(), remaining).toInt()
                                rw.write(zero, 0, n)
                                remaining -= n
                            }
                            rw.fd.sync()
                        }
                    }
                } catch (_: Throwable) { /* best effort */ }
                f.delete()
            }
        }
    }

    private fun deriveKey(
        head: ArchiveReader.ParsedHead, password: CharArray?, hybridPriv: ByteArray?
    ): ByteArray? {
        if (!head.header.isEncrypted) return null
        var pwKey: ByteArray? = null
        var pqKey: ByteArray? = null
        if (head.header.isPassword) {
            require(password != null && password.isNotEmpty()) { "Password required" }
            pwKey = Kdf.derive(password, head.kdfSalt!!, head.kdfIters)
        }
        if (head.header.isPq) {
            require(hybridPriv != null) { "PQ private key required" }
            pqKey = HybridKem.decapsulate(hybridPriv, head.pqCiphertext!!)
        }
        if (pwKey != null && pqKey == null) return pwKey
        if (pwKey == null && pqKey != null) return pqKey
        val shake = org.bouncycastle.crypto.digests.SHAKEDigest(256)
        shake.update(pwKey!!, 0, pwKey.size)
        shake.update(pqKey!!, 0, pqKey.size)
        val info = "ZUPT-PWPQ-v1".toByteArray(Charsets.US_ASCII)
        shake.update(info, 0, info.size)
        val out = ByteArray(64); shake.doFinal(out, 0, 64)
        pwKey.wipe(); pqKey.wipe()
        return out
    }
}
