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
import java.io.DataInput
import java.io.DataOutput
import java.util.UUID

object Format {
    val MAGIC = byteArrayOf(0x5A, 0x55, 0x50, 0x54, 0x31, 0x00) // "ZUPT1\0"
    const val VERSION_MAJOR: Byte = 1
    const val VERSION_MINOR: Byte = 1

    const val FLAG_ENCRYPTED = 1 shl 0
    const val FLAG_PQ        = 1 shl 1
    const val FLAG_PASSWORD  = 1 shl 2
    const val FLAG_SOLID     = 1 shl 3

    const val DEFAULT_BLOCK_LOG2 = 20  // 1 MiB
    const val HEADER_SIZE = 50         // 6 + 1 + 1 + 4 + 16 + 8 + 1 + 1 + 1 + 11
}

data class ArchiveHeader(
    val versionMajor: Byte,
    val versionMinor: Byte,
    val flags: Int,
    val uuid: UUID,
    val timestampMicros: Long,
    val codec: CodecId,
    val level: Byte,
    val blockLog2: Byte
) {
    val isEncrypted get() = (flags and Format.FLAG_ENCRYPTED) != 0
    val isPq get() = (flags and Format.FLAG_PQ) != 0
    val isPassword get() = (flags and Format.FLAG_PASSWORD) != 0
    val isSolid get() = (flags and Format.FLAG_SOLID) != 0
    val blockSize: Int get() = 1 shl blockLog2.toInt()

    fun write(out: DataOutput) {
        out.write(Format.MAGIC)                   // 6
        out.writeByte(versionMajor.toInt())       // 1
        out.writeByte(versionMinor.toInt())       // 1
        out.writeInt(flags)                        // 4
        val msb = uuid.mostSignificantBits
        val lsb = uuid.leastSignificantBits
        out.writeLong(msb); out.writeLong(lsb)    // 16
        out.writeLong(timestampMicros)             // 8
        out.writeByte(codec.byte.toInt())          // 1
        out.writeByte(level.toInt())               // 1
        out.writeByte(blockLog2.toInt())           // 1
        out.write(ByteArray(11))                   // 11 reserved
    }

    companion object {
        fun read(ins: DataInput): ArchiveHeader {
            val magic = ByteArray(6); ins.readFully(magic)
            require(magic.contentEquals(Format.MAGIC)) { "Not a Zupt archive (bad magic)" }
            val vMaj = ins.readByte()
            val vMin = ins.readByte()
            require(vMaj == Format.VERSION_MAJOR) {
                "Unsupported archive major version: $vMaj (expected ${Format.VERSION_MAJOR})"
            }
            val flags = ins.readInt()
            val msb = ins.readLong(); val lsb = ins.readLong()
            val uuid = UUID(msb, lsb)
            val ts = ins.readLong()
            val codec = CodecId.fromByte(ins.readByte())
            val level = ins.readByte()
            val blk = ins.readByte()
            val reserved = ByteArray(11); ins.readFully(reserved)
            return ArchiveHeader(vMaj, vMin, flags, uuid, ts, codec, level, blk)
        }
    }
}

data class FileEntry(
    val path: String,
    val size: Long,
    val mtimeMicros: Long,
    val mode: Int,
    val xxh64: Long,
    val blockStartIndex: Int = 0,   // which block in the block table this file starts at
    val blockCount: Int = -1        // number of blocks (-1 = all remaining; legacy single-file)
) {
    fun write(out: DataOutput) {
        val pathBytes = path.toByteArray(Charsets.UTF_8)
        require(pathBytes.size <= 65535) { "Path too long: ${pathBytes.size} bytes" }
        out.writeShort(pathBytes.size)
        out.write(pathBytes)
        out.writeLong(size)
        out.writeLong(mtimeMicros)
        out.writeInt(mode)
        out.writeLong(xxh64)
        out.writeInt(blockStartIndex)
        out.writeInt(blockCount)
    }

    companion object {
        fun read(ins: DataInput): FileEntry {
            val len = ins.readUnsignedShort()
            val pathBytes = ByteArray(len); ins.readFully(pathBytes)
            val size = ins.readLong()
            val mtime = ins.readLong()
            val mode = ins.readInt()
            val xxh = ins.readLong()
            val startIdx = ins.readInt()
            val blkCount = ins.readInt()
            return FileEntry(String(pathBytes, Charsets.UTF_8), size, mtime, mode, xxh, startIdx, blkCount)
        }
    }
}

data class BlockEntry(val rawSize: Int, val compSize: Int, val xxh64: Long) {
    fun write(out: DataOutput) {
        out.writeInt(rawSize); out.writeInt(compSize); out.writeLong(xxh64)
    }
    companion object {
        fun read(ins: DataInput) = BlockEntry(ins.readInt(), ins.readInt(), ins.readLong())
    }
}
