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

package co.securityops.zupt.core.io

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import java.io.ByteArrayOutputStream

object SafFiles {
    fun readBytes(ctx: Context, uri: Uri, sizeCap: Long = 512L * 1024 * 1024): ByteArray {
        ctx.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Cannot open input stream for $uri" }
            val bos = ByteArrayOutputStream()
            val buf = ByteArray(64 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                total += n
                require(total <= sizeCap) { "File exceeds cap ($sizeCap bytes)" }
                bos.write(buf, 0, n)
            }
            return bos.toByteArray()
        }
    }

    fun writeBytes(ctx: Context, uri: Uri, bytes: ByteArray) {
        // CRITICAL: mode MUST be "w" (binary truncate), NOT "wt".
        // The "t" flag is a text-mode hint that some DocumentProvider implementations
        // (cloud, SAF shims) honor by translating line endings or normalizing Unicode —
        // corrupting binary data (archives, keys) and causing GCM auth failures later.
        ctx.contentResolver.openOutputStream(uri, "w").use { out ->
            requireNotNull(out) { "Cannot open output stream for $uri" }
            out.write(bytes)
            out.flush()
        }
    }

    fun displayName(ctx: Context, uri: Uri): String? {
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) return c.getString(0)
        }
        return uri.lastPathSegment
    }

    fun size(ctx: Context, uri: Uri): Long {
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst() && !c.isNull(0)) return c.getLong(0)
        }
        return -1
    }
}
