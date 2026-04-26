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

package co.securityops.zupt.core.crypto

/**
 * XXH64 — Yann Collet's xxHash64. Pure-Kotlin streaming implementation.
 * Matches reference: https://github.com/Cyan4973/xxHash
 */
class Xxh64(seed: Long = 0L) {
    companion object {
        private const val P1 = -7046029288634856825L  // 0x9E3779B185EBCA87
        private const val P2 = -4417276706812531889L  // 0xC2B2AE3D27D4EB4F
        private const val P3 = 1609587929392839161L   // 0x165667B19E3779F9
        private const val P4 = -8796714831421723037L  // 0x85EBCA77C2B2AE63
        private const val P5 = 2870177450012600261L   // 0x27D4EB2F165667C5

        fun hash(data: ByteArray, seed: Long = 0L): Long {
            val h = Xxh64(seed)
            h.update(data, 0, data.size)
            return h.digest()
        }
    }

    private var v1 = seed + P1 + P2
    private var v2 = seed + P2
    private var v3 = seed + 0
    private var v4 = seed - P1
    private val buf = ByteArray(32)
    private var bufLen = 0
    private var total: Long = 0
    private var seedCopy = seed

    fun update(data: ByteArray, off: Int, len: Int) {
        var o = off
        var remain = len
        total += remain
        if (bufLen > 0) {
            val fill = minOf(32 - bufLen, remain)
            System.arraycopy(data, o, buf, bufLen, fill)
            bufLen += fill
            o += fill; remain -= fill
            if (bufLen == 32) { consumeBlock(buf, 0); bufLen = 0 }
        }
        while (remain >= 32) {
            consumeBlock(data, o)
            o += 32; remain -= 32
        }
        if (remain > 0) {
            System.arraycopy(data, o, buf, 0, remain)
            bufLen = remain
        }
    }

    private fun consumeBlock(src: ByteArray, o: Int) {
        v1 = round(v1, readLongLE(src, o))
        v2 = round(v2, readLongLE(src, o + 8))
        v3 = round(v3, readLongLE(src, o + 16))
        v4 = round(v4, readLongLE(src, o + 24))
    }

    fun digest(): Long {
        var h: Long
        if (total >= 32) {
            h = rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18)
            h = mergeRound(h, v1)
            h = mergeRound(h, v2)
            h = mergeRound(h, v3)
            h = mergeRound(h, v4)
        } else {
            h = seedCopy + P5
        }
        h += total

        var i = 0
        while (bufLen - i >= 8) {
            val k1 = round(0, readLongLE(buf, i))
            h = (rotl(h xor k1, 27) * P1) + P4
            i += 8
        }
        if (bufLen - i >= 4) {
            h = (rotl(h xor ((readIntLE(buf, i).toLong() and 0xFFFFFFFFL) * P1), 23) * P2) + P3
            i += 4
        }
        while (i < bufLen) {
            h = rotl(h xor ((buf[i].toInt() and 0xFF).toLong() * P5), 11) * P1
            i++
        }
        h = h xor (h ushr 33); h *= P2
        h = h xor (h ushr 29); h *= P3
        h = h xor (h ushr 32)
        return h
    }

    private fun round(acc: Long, input: Long): Long {
        var a = acc + input * P2
        a = rotl(a, 31)
        return a * P1
    }

    private fun mergeRound(acc: Long, v: Long): Long {
        val r = round(0, v)
        return (acc xor r) * P1 + P4
    }

    private fun rotl(x: Long, r: Int): Long = (x shl r) or (x ushr (64 - r))

    private fun readLongLE(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xFF) or
        ((b[o+1].toLong() and 0xFF) shl 8) or
        ((b[o+2].toLong() and 0xFF) shl 16) or
        ((b[o+3].toLong() and 0xFF) shl 24) or
        ((b[o+4].toLong() and 0xFF) shl 32) or
        ((b[o+5].toLong() and 0xFF) shl 40) or
        ((b[o+6].toLong() and 0xFF) shl 48) or
        ((b[o+7].toLong() and 0xFF) shl 56)

    private fun readIntLE(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or
        ((b[o+1].toInt() and 0xFF) shl 8) or
        ((b[o+2].toInt() and 0xFF) shl 16) or
        ((b[o+3].toInt() and 0xFF) shl 24)
}
