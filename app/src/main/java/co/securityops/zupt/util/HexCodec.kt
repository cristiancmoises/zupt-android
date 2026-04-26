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

package co.securityops.zupt.util

fun ByteArray.toHex(): String {
    val hex = "0123456789abcdef".toCharArray()
    val out = CharArray(this.size * 2)
    var j = 0
    for (b in this) {
        val v = b.toInt() and 0xFF
        out[j++] = hex[v ushr 4]
        out[j++] = hex[v and 0x0F]
    }
    return String(out)
}

fun String.fromHex(): ByteArray {
    val clean = this.replace(Regex("\\s"), "")
    require(clean.length % 2 == 0) { "Hex length must be even" }
    val out = ByteArray(clean.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(clean[i * 2], 16)
        val lo = Character.digit(clean[i * 2 + 1], 16)
        require(hi >= 0 && lo >= 0) { "Non-hex character at ${i * 2}" }
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}

fun formatSize(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val units = listOf("KiB", "MiB", "GiB", "TiB")
    var value = bytes.toDouble() / 1024.0
    var i = 0
    while (value >= 1024.0 && i < units.size - 1) {
        value /= 1024.0
        i++
    }
    return "%.2f %s".format(value, units[i])
}

fun formatDuration(ms: Long): String {
    if (ms < 1000) return "${ms} ms"
    val s = ms / 1000.0
    if (s < 60) return "%.2f s".format(s)
    val m = (s / 60).toInt()
    val r = s - m * 60
    return "${m}m %.1fs".format(r)
}
