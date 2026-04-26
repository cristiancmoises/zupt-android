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

package co.securityops.zupt.core.codec

import java.util.zip.Deflater
import java.util.zip.Inflater

enum class CodecId(val byte: Byte, val label: String) {
    STORE(0, "Store"),
    DEFLATE(1, "Zupt-LZHP"),        // Universal Deflate-based codec
    VAPTVUPT(2, "VaptVupt");        // Slot reserved for NDK-backed VaptVupt

    companion object {
        fun fromByte(b: Byte): CodecId =
            values().firstOrNull { it.byte == b }
                ?: throw IllegalArgumentException("Unknown codec id: $b")
    }
}

interface Codec {
    val id: CodecId
    fun compress(raw: ByteArray, level: Int): ByteArray
    fun decompress(comp: ByteArray, rawSize: Int): ByteArray
}

object StoreCodec : Codec {
    override val id = CodecId.STORE
    override fun compress(raw: ByteArray, level: Int): ByteArray = raw
    override fun decompress(comp: ByteArray, rawSize: Int): ByteArray = comp
}

/**
 * Deflate codec — Zupt-LZHP universal.
 * Maps level 1–9 directly to java.util.zip.Deflater BEST_SPEED..BEST_COMPRESSION.
 */
object DeflateCodec : Codec {
    override val id = CodecId.DEFLATE

    override fun compress(raw: ByteArray, level: Int): ByteArray {
        val def = Deflater(level.coerceIn(1, 9), /* nowrap = */ true)
        try {
            def.setInput(raw)
            def.finish()
            // Upper bound: raw + 64 header
            val out = ByteArray(raw.size + 64)
            var written = 0
            while (!def.finished()) {
                if (written == out.size) {
                    // grow
                    val bigger = out.copyOf(out.size * 2)
                    return compressLarge(raw, level, bigger, written, def)
                }
                written += def.deflate(out, written, out.size - written)
            }
            return out.copyOf(written)
        } finally {
            def.end()
        }
    }

    private fun compressLarge(
        raw: ByteArray, level: Int, initial: ByteArray, startWritten: Int, def: Deflater
    ): ByteArray {
        var out = initial; var written = startWritten
        while (!def.finished()) {
            if (written == out.size) out = out.copyOf(out.size * 2)
            written += def.deflate(out, written, out.size - written)
        }
        return out.copyOf(written)
    }

    override fun decompress(comp: ByteArray, rawSize: Int): ByteArray {
        val inf = Inflater(/* nowrap = */ true)
        try {
            inf.setInput(comp)
            val out = ByteArray(rawSize)
            var written = 0
            while (written < rawSize) {
                val n = inf.inflate(out, written, rawSize - written)
                written += n
                if (n == 0) {
                    // Legitimate end-of-stream signals:
                    //   - inf.finished() → raw deflate stream consumed fully
                    //   - written == rawSize → we have everything we asked for
                    // needsInput() returns true even at EOF with nowrap=true, so
                    // it is NOT a reliable failure signal — only break on it.
                    if (inf.finished()) break
                    if (inf.needsDictionary())
                        throw IllegalStateException("Deflate stream requires preset dictionary")
                    if (inf.needsInput() && written < rawSize)
                        throw IllegalStateException("Deflate truncated: got $written / $rawSize B")
                    break
                }
            }
            require(written == rawSize) {
                "Decompressed size mismatch: expected $rawSize, got $written"
            }
            return out
        } finally {
            inf.end()
        }
    }
}

/**
 * VaptVupt — reserved slot for the native NDK codec.
 * Until libvaptvupt.so is shipped, this alias routes to Deflate with a marker
 * so archives remain cross-platform; when NDK lands, switch the impl without
 * changing the archive format.
 */
object VaptVuptCodec : Codec {
    override val id = CodecId.VAPTVUPT
    override fun compress(raw: ByteArray, level: Int) = DeflateCodec.compress(raw, level)
    override fun decompress(comp: ByteArray, rawSize: Int) = DeflateCodec.decompress(comp, rawSize)
}

object Codecs {
    fun byId(id: CodecId): Codec = when (id) {
        CodecId.STORE -> StoreCodec
        CodecId.DEFLATE -> DeflateCodec
        CodecId.VAPTVUPT -> VaptVuptCodec
    }
}
