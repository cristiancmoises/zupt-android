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
import co.securityops.zupt.core.crypto.*
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Archive writer — single-file input mode.
 * Produces a .zupt blob holding one logical file split into fixed-size blocks.
 */
object ArchiveWriter {

    data class Input(
        val name: String,
        val bytes: ByteArray,
        val mtimeMicros: Long = System.currentTimeMillis() * 1000L,
        val mode: Int = 0b110_100_100  // 0o644
    )

    data class Options(
        val codec: CodecId = CodecId.DEFLATE,
        val level: Int = 6,
        val solid: Boolean = false,
        val password: CharArray? = null,
        val pqRecipientPublic: ByteArray? = null,  // hybrid public (1216 B)
        val blockLog2: Int = Format.DEFAULT_BLOCK_LOG2
    )

    data class Result(val bytes: ByteArray, val blockCount: Int, val ratio: Double)

    fun write(file: Input, opts: Options): Result {
        val codec = Codecs.byId(opts.codec)
        val blockSize = 1 shl opts.blockLog2

        // ─── Compute per-file xxh64 and slice into blocks ───────────────
        val fileXxh = Xxh64.hash(file.bytes)
        val blocks = mutableListOf<Pair<ByteArray, BlockEntry>>()
        var off = 0
        while (off < file.bytes.size) {
            val end = minOf(off + blockSize, file.bytes.size)
            val raw = file.bytes.copyOfRange(off, end)
            val comp = codec.compress(raw, opts.level)
            val useComp = if (comp.size < raw.size) comp else raw
            val usedCodecSize = useComp.size
            val xxh = Xxh64.hash(raw)
            blocks += useComp to BlockEntry(raw.size, usedCodecSize, xxh)
            off = end
        }

        // ─── Build flags + header ──────────────────────────────────────
        var flags = 0
        val needsEnc = opts.password != null || opts.pqRecipientPublic != null
        if (needsEnc) flags = flags or Format.FLAG_ENCRYPTED
        if (opts.password != null) flags = flags or Format.FLAG_PASSWORD
        if (opts.pqRecipientPublic != null) flags = flags or Format.FLAG_PQ
        if (opts.solid) flags = flags or Format.FLAG_SOLID

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

        // ─── Assemble pre-payload ──────────────────────────────────────
        val pre = ByteArrayOutputStream()
        val dPre = DataOutputStream(pre)
        header.write(dPre)

        var pwKey: ByteArray? = null
        var pqKey: ByteArray? = null

        if (opts.password != null) {
            val salt = secureRandomBytes(32)
            val iters = Kdf.DEFAULT_ITERS
            dPre.write(salt)
            dPre.writeInt(iters)
            pwKey = Kdf.derive(opts.password, salt, iters)
        }
        if (opts.pqRecipientPublic != null) {
            val enc = HybridKem.encapsulate(opts.pqRecipientPublic)
            dPre.write(enc.ciphertext)
            pqKey = enc.sharedSecret  // 64 bytes
        }

        // File table (one entry) — written BEFORE block table
        dPre.writeInt(1)
        FileEntry(file.name, file.bytes.size.toLong(), file.mtimeMicros, file.mode, fileXxh)
            .write(dPre)

        // Block table
        dPre.writeInt(blocks.size)
        for ((_, be) in blocks) be.write(dPre)

        val preBytes = pre.toByteArray()

        // ─── Concat payload bytes (plaintext) ──────────────────────────
        val payloadPlain = ByteArrayOutputStream()
        for ((data, _) in blocks) payloadPlain.write(data)
        val payloadPlainBytes = payloadPlain.toByteArray()

        // ─── AES-256-GCM over payload, HMAC-SHA256 over header for integrity ───
        val finalKey = combineKeys(pwKey, pqKey)

        val body = ByteArrayOutputStream()
        val dBody = DataOutputStream(body)
        dBody.write(preBytes)

        val finalBytes: ByteArray
        if (finalKey != null) {
            val encKey = Aead.deriveEncKey(finalKey)
            val nonce = secureRandomBytes(Aead.NONCE_SIZE)
            dBody.write(nonce)
            // AAD binds the ciphertext to the entire preamble + nonce, preventing
            // header tampering. GCM tag (16B) is appended to ciphertext automatically.
            val aad = preBytes + nonce
            val ctWithTag = Aead.encrypt(encKey, nonce, aad, payloadPlainBytes)
            dBody.write(ctWithTag)
            encKey.wipe()
            finalKey.wipe()
            finalBytes = body.toByteArray()
        } else {
            // No encryption: append header HMAC using a public zero key.
            // NOT a security feature — just a consistent "tail" for parser simplicity.
            dBody.write(payloadPlainBytes)
            val headerMac = Mac.getInstance("HmacSHA256")
            headerMac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            headerMac.update(body.toByteArray())
            dBody.write(headerMac.doFinal())
            finalBytes = body.toByteArray()
        }

        pwKey?.wipe()
        pqKey?.wipe()

        val ratio = if (file.bytes.isNotEmpty())
            finalBytes.size.toDouble() / file.bytes.size.toDouble() else 1.0
        return Result(finalBytes, blocks.size, ratio)
    }

    private fun combineKeys(pw: ByteArray?, pq: ByteArray?): ByteArray? {
        if (pw == null && pq == null) return null
        if (pw != null && pq == null) return pw
        if (pw == null && pq != null) return pq
        // Both present — mix with SHAKE256 to produce 64 B final key
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
 * Reader — verifies HMAC, decrypts, decompresses, yields the original file.
 * Also provides info-only and verify-only modes without full decode.
 */
object ArchiveReader {

    data class ParsedHead(
        val header: ArchiveHeader,
        val kdfSalt: ByteArray?,
        val kdfIters: Int,
        val pqCiphertext: ByteArray?,
        val files: List<FileEntry>,
        val blocks: List<BlockEntry>,
        val preBytes: ByteArray,
        val ivStart: Int,              // -1 if unencrypted
        val payloadStart: Int,
        val payloadSize: Int,
        val tagStart: Int
    )

    fun parse(archive: ByteArray): ParsedHead {
        val din = DataInputStream(archive.inputStream())
        val header = ArchiveHeader.read(din)
        var consumed = Format.HEADER_SIZE

        var salt: ByteArray? = null
        var iters = 0
        if (header.isPassword) {
            salt = ByteArray(32); din.readFully(salt); consumed += 32
            iters = din.readInt(); consumed += 4
        }
        var pqCt: ByteArray? = null
        if (header.isPq) {
            pqCt = ByteArray(HybridKem.HYBRID_CT); din.readFully(pqCt)
            consumed += HybridKem.HYBRID_CT
        }

        val fileCount = din.readInt(); consumed += 4
        val files = ArrayList<FileEntry>(fileCount)
        repeat(fileCount) {
            val e = FileEntry.read(din)
            files += e
            consumed += 2 + e.path.toByteArray(Charsets.UTF_8).size + 8 + 8 + 4 + 8 + 4 + 4
        }

        val blockCount = din.readInt(); consumed += 4
        val blocks = ArrayList<BlockEntry>(blockCount)
        repeat(blockCount) {
            blocks += BlockEntry.read(din); consumed += 16
        }

        val preBytes = archive.copyOfRange(0, consumed)
        val ivStart: Int
        val payloadStart: Int
        val tagStart: Int
        val payloadSize: Int

        if (header.isEncrypted) {
            // Layout: [preBytes][nonce:12B][ciphertext+GCM_tag:N+16B]
            // GCM tag is inline with ciphertext, no trailing HMAC.
            ivStart = consumed
            payloadStart = ivStart + Aead.NONCE_SIZE
            tagStart = archive.size           // no separate trailing tag
            payloadSize = archive.size - payloadStart
        } else {
            // Unencrypted: [preBytes][payload][headerHmac:32B]
            ivStart = -1
            payloadStart = consumed
            tagStart = archive.size - 32
            payloadSize = tagStart - payloadStart
        }
        require(payloadSize >= 0) { "Archive truncated" }

        return ParsedHead(
            header, salt, iters, pqCt, files, blocks,
            preBytes, ivStart, payloadStart, payloadSize, tagStart
        )
    }

    /** Verify GCM tag (implicit in decrypt) and every block's XXH64. */
    fun verify(
        archive: ByteArray,
        password: CharArray? = null,
        hybridPriv: ByteArray? = null
    ): VerifyReport {
        val head = parse(archive)
        val key = deriveKey(head, password, hybridPriv)

        var tagOk = true
        val plain: ByteArray? = if (head.header.isEncrypted) {
            if (key == null) return VerifyReport(false, head.blocks.size, emptyList(), head.header, head.files.size)
            val encKey = Aead.deriveEncKey(key)
            val nonce = archive.copyOfRange(head.ivStart, head.ivStart + Aead.NONCE_SIZE)
            val aad = head.preBytes + nonce
            val ctWithTag = archive.copyOfRange(head.payloadStart, head.payloadStart + head.payloadSize)
            try {
                Aead.decrypt(encKey, nonce, aad, ctWithTag)
            } catch (_: Throwable) {
                tagOk = false
                null
            }.also { encKey.wipe() }
        } else {
            // Unencrypted: check the trailing header HMAC
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            mac.update(archive, 0, head.tagStart)
            val expected = mac.doFinal()
            val given = archive.copyOfRange(head.tagStart, archive.size)
            tagOk = java.security.MessageDigest.isEqual(expected, given)
            if (tagOk) archive.copyOfRange(head.payloadStart, head.payloadStart + head.payloadSize) else null
        }

        val badBlocks = mutableListOf<Int>()
        if (plain != null) {
            var off = 0
            head.blocks.forEachIndexed { i, be ->
                val slice = plain.copyOfRange(off, off + be.compSize)
                off += be.compSize
                val codec = Codecs.byId(head.header.codec)
                val raw = try {
                    if (be.compSize == be.rawSize) slice
                    else codec.decompress(slice, be.rawSize)
                } catch (_: Throwable) { null }
                if (raw == null || Xxh64.hash(raw) != be.xxh64) badBlocks += i
            }
        }

        key?.wipe()
        return VerifyReport(
            tagOk = tagOk,
            blocksChecked = head.blocks.size,
            badBlocks = badBlocks,
            header = head.header,
            fileCount = head.files.size
        )
    }

    fun extract(
        archive: ByteArray,
        password: CharArray? = null,
        hybridPriv: ByteArray? = null
    ): Pair<FileEntry, ByteArray> {
        val head = parse(archive)
        val key = deriveKey(head, password, hybridPriv)

        val plain: ByteArray = if (head.header.isEncrypted) {
            if (key == null) throw SecurityException("Archive is encrypted but no key material provided")
            val encKey = Aead.deriveEncKey(key)
            val nonce = archive.copyOfRange(head.ivStart, head.ivStart + Aead.NONCE_SIZE)
            val aad = head.preBytes + nonce
            val ctWithTag = archive.copyOfRange(head.payloadStart, head.payloadStart + head.payloadSize)
            try {
                Aead.decrypt(encKey, nonce, aad, ctWithTag)
            } catch (t: javax.crypto.AEADBadTagException) {
                val hint = buildString {
                    append("Authentication failed. ")
                    if (head.header.isPassword && head.header.isPq) {
                        append("Archive needs BOTH password AND PQ private key.")
                    } else if (head.header.isPassword) {
                        append("Check the password.")
                    } else if (head.header.isPq) {
                        append("PQ private key does not match the public key used to encrypt.")
                    } else {
                        append("Archive appears tampered.")
                    }
                }
                throw SecurityException(hint, t)
            } finally {
                encKey.wipe()
            }
        } else {
            // Verify the zero-key header HMAC (integrity only — not a secret)
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            mac.update(archive, 0, head.tagStart)
            val expected = mac.doFinal()
            val given = archive.copyOfRange(head.tagStart, archive.size)
            if (!java.security.MessageDigest.isEqual(expected, given))
                throw SecurityException("Header integrity check failed — archive appears corrupted.")
            archive.copyOfRange(head.payloadStart, head.payloadStart + head.payloadSize)
        }

        // Reassemble file from blocks
        val fileEntry = head.files.first()
        require(fileEntry.size <= Int.MAX_VALUE) {
            "File too large for single-shot extraction: ${fileEntry.size} bytes"
        }
        val out = ByteArray(fileEntry.size.toInt())
        var srcOff = 0; var dstOff = 0
        val codec = Codecs.byId(head.header.codec)
        for ((i, be) in head.blocks.withIndex()) {
            if (srcOff + be.compSize > plain.size) {
                throw SecurityException("Payload truncated at block $i (need ${be.compSize} B at offset $srcOff, have ${plain.size - srcOff})")
            }
            val comp = plain.copyOfRange(srcOff, srcOff + be.compSize)
            srcOff += be.compSize
            val raw = try {
                if (be.compSize == be.rawSize) comp
                else codec.decompress(comp, be.rawSize)
            } catch (t: Throwable) {
                throw SecurityException("Block $i decompress failed (${head.header.codec.label}, ${be.compSize}→${be.rawSize}B): ${t.message}", t)
            }
            if (Xxh64.hash(raw) != be.xxh64)
                throw SecurityException("Block $i XXH64 mismatch — archive corrupted")
            if (dstOff + raw.size > out.size) {
                throw SecurityException("Block $i overflows file size (dstOff=$dstOff raw=${raw.size} fileSize=${out.size})")
            }
            System.arraycopy(raw, 0, out, dstOff, raw.size)
            dstOff += raw.size
        }
        if (dstOff != out.size) {
            throw SecurityException("File underfilled: wrote $dstOff of ${out.size} bytes")
        }
        if (Xxh64.hash(out) != fileEntry.xxh64)
            throw SecurityException("File XXH64 mismatch — corruption after reassembly")

        key?.wipe()
        return fileEntry to out
    }

    private fun deriveKey(
        head: ParsedHead, password: CharArray?, hybridPriv: ByteArray?
    ): ByteArray? {
        if (!head.header.isEncrypted) return null
        var pwKey: ByteArray? = null
        var pqKey: ByteArray? = null
        if (head.header.isPassword) {
            require(password != null && password.isNotEmpty()) {
                "Archive is password-protected — password required"
            }
            pwKey = Kdf.derive(password, head.kdfSalt!!, head.kdfIters)
        }
        if (head.header.isPq) {
            require(hybridPriv != null) { "Archive is PQ-encrypted — PQ private key required" }
            pqKey = HybridKem.decapsulate(hybridPriv, head.pqCiphertext!!)
        }
        if (pwKey != null && pqKey == null) return pwKey
        if (pwKey == null && pqKey != null) return pqKey
        // Both present — mix (same as writer)
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

data class VerifyReport(
    val tagOk: Boolean,
    val blocksChecked: Int,
    val badBlocks: List<Int>,
    val header: ArchiveHeader,
    val fileCount: Int
) {
    val ok: Boolean get() = tagOk && badBlocks.isEmpty()
}
