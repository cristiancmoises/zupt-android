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
package co.securityops.zupt.test

import co.securityops.zupt.core.archive.ArchiveReader
import co.securityops.zupt.core.archive.StreamingReader
import co.securityops.zupt.core.archive.StreamingWriter
import co.securityops.zupt.core.codec.CodecId
import co.securityops.zupt.core.crypto.HybridKem
import java.io.File
import java.security.MessageDigest
import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider

fun main() {
    Security.insertProviderAt(BouncyCastleProvider(), 1)
    Security.insertProviderAt(BouncyCastlePQCProvider(), 2)

    val scratchDir = File("/tmp/zupt-multi").apply { mkdirs() }
    val kp = HybridKem.generateKeypair()
    val pw = "hunter2".toCharArray()

    // Create 3 files of different sizes
    val f1 = makeFile(scratchDir, "doc.txt", 10_000, seed = 1)
    val f2 = makeFile(scratchDir, "images/photo.jpg", 2_500_000, seed = 2)
    val f3 = makeFile(scratchDir, "logs/server.log", 500_000, seed = 3)

    val archive = File.createTempFile("multi-", ".zupt", scratchDir)

    // Compress all three
    println("=== Compress 3 files ===")
    archive.outputStream().use { out ->
        val result = StreamingWriter.writeMulti(
            output = out,
            scratchDir = scratchDir,
            opts = StreamingWriter.MultiOptions(
                codec = CodecId.DEFLATE, level = 6,
                password = pw.copyOf(),
                pqRecipientPublic = kp.publicKey,
                files = listOf(
                    StreamingWriter.FileInput("doc.txt", f1.length(), { f1.inputStream() }),
                    StreamingWriter.FileInput("images/photo.jpg", f2.length(), { f2.inputStream() }),
                    StreamingWriter.FileInput("logs/server.log", f3.length(), { f3.inputStream() })
                )
            )
        )
        println("  archive ${archive.length()} B blocks=${result.blockCount} ratio=${"%.2f".format(result.ratio)}")
    }

    // Peek header to list files
    val head = ArchiveReader.parse(archive.readBytes())
    println("\n=== Header (v${head.header.versionMajor}.${head.header.versionMinor}): ${head.files.size} files ===")
    for (f in head.files) {
        println("  ${f.path}  size=${f.size}B  blocks=[${f.blockStartIndex}..${f.blockStartIndex + f.blockCount - 1}]  xxh=${"%x".format(f.xxh64)}")
    }

    // Extract each file individually — single-file API iterates by rewriting head.files
    // For now we use a helper that extracts one file at a time by slicing the block list.
    println("\n=== Extract each file ===")
    val extractedHashes = mutableMapOf<String, String>()
    for ((idx, fileEntry) in head.files.withIndex()) {
        val outFile = File.createTempFile("extracted-", ".bin", scratchDir)
        archive.inputStream().use { archIn ->
            outFile.outputStream().use { fileOut ->
                // Extract this specific file index
                StreamingReader.extractFileAt(
                    archiveInput = archIn,
                    archiveSize = archive.length(),
                    output = fileOut,
                    scratchDir = scratchDir,
                    password = pw.copyOf(),
                    hybridPriv = kp.privateKey,
                    fileIndex = idx
                )
            }
        }
        val sha = MessageDigest.getInstance("SHA-256")
        outFile.inputStream().buffered(256 * 1024).use { inp ->
            val buf = ByteArray(64 * 1024)
            while (true) { val n = inp.read(buf); if (n <= 0) break; sha.update(buf, 0, n) }
        }
        extractedHashes[fileEntry.path] = sha.digest().joinToString("") { "%02x".format(it) }
        println("  ${fileEntry.path}: ${outFile.length()}B sha=${extractedHashes[fileEntry.path]!!.take(16)}…")
        outFile.delete()
    }

    val expected = mapOf(
        "doc.txt" to shaFile(f1),
        "images/photo.jpg" to shaFile(f2),
        "logs/server.log" to shaFile(f3)
    )
    println("\n=== Verification ===")
    for ((path, h) in expected) {
        val got = extractedHashes[path]
        val ok = got == h
        println("  $path  match=$ok")
        if (!ok) error("HASH MISMATCH on $path (expected ${h.take(16)}, got ${got?.take(16) ?: "null"})")
    }
    println("\nALL GOOD")

    f1.delete(); f2.delete(); f3.delete(); archive.delete()
}

private fun makeFile(dir: File, name: String, size: Long, seed: Int): File {
    val f = File.createTempFile("in-${seed}-", "-${name.replace('/', '_')}", dir)
    val rng = java.util.Random(seed.toLong())
    f.outputStream().buffered().use { out ->
        val buf = ByteArray(64 * 1024)
        var written = 0L
        while (written < size) {
            val n = minOf(buf.size.toLong(), size - written).toInt()
            rng.nextBytes(buf)
            out.write(buf, 0, n)
            written += n
        }
    }
    return f
}

private fun shaFile(f: File): String {
    val sha = MessageDigest.getInstance("SHA-256")
    f.inputStream().buffered(256 * 1024).use { inp ->
        val buf = ByteArray(64 * 1024)
        while (true) { val n = inp.read(buf); if (n <= 0) break; sha.update(buf, 0, n) }
    }
    return sha.digest().joinToString("") { "%02x".format(it) }
}
