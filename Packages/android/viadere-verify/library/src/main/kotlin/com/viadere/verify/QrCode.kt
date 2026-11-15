package com.viadere.verify

/**
 * QR code encoder (ISO/IEC 18004): byte mode, error correction level M, versions 1 to 10, lowest-penalty mask.
 *
 * A line-for-line port of the encoder in the web component (`Server/Public/verify-button/v1/viadere-verify.js`), which the browser test checks
 * module for module against the `qrcode` reference library. The unit tests here compare against vectors produced and cross-checked that way.
 * A session link is 30 to 38 bytes, so it always fits in version 3 or 4. No dependency: nothing to update, nothing to audit but this file.
 */
object QrCode {
    private val ECC_PER_BLOCK = intArrayOf(0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26)
    private val ECC_BLOCKS = intArrayOf(0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5)

    private fun rawModules(ver: Int): Int {
        var result = (16 * ver + 128) * ver + 64
        if (ver >= 2) {
            val n = ver / 7 + 2
            result -= (25 * n - 10) * n - 55
            if (ver >= 7) result -= 36
        }
        return result
    }

    private fun dataCodewords(ver: Int): Int = rawModules(ver) / 8 - ECC_PER_BLOCK[ver] * ECC_BLOCKS[ver]

    private fun gfMul(x: Int, y: Int): Int {
        var z = 0
        for (i in 7 downTo 0) {
            z = (z shl 1) xor ((z ushr 7) * 0x11D)
            z = z xor (((y ushr i) and 1) * x)
        }
        return z and 0xFF
    }

    private fun rsDivisor(degree: Int): IntArray {
        val result = IntArray(degree)
        result[degree - 1] = 1
        var root = 1
        repeat(degree) {
            for (j in result.indices) {
                result[j] = gfMul(result[j], root)
                if (j + 1 < result.size) result[j] = result[j] xor result[j + 1]
            }
            root = gfMul(root, 0x02)
        }
        return result
    }

    private fun rsRemainder(data: List<Int>, divisor: IntArray): List<Int> {
        val result = ArrayDeque<Int>()
        repeat(divisor.size) { result.addLast(0) }
        for (b in data) {
            val factor = b xor result.removeFirst()
            result.addLast(0)
            for (i in divisor.indices) result[i] = result[i] xor gfMul(divisor[i], factor)
        }
        return result.toList()
    }

    /** The module matrix (`[y][x]`, `true` = dark) without quiet zone, or `null` when `text` does not fit version 10. */
    fun matrix(text: String): Array<BooleanArray>? {
        val bytes = text.toByteArray(Charsets.UTF_8).map { it.toInt() and 0xFF }
        val ver = (1..10).firstOrNull { v -> 4 + (if (v < 10) 8 else 16) + 8 * bytes.size <= dataCodewords(v) * 8 } ?: return null

        val bits = ArrayList<Int>()
        fun put(value: Int, length: Int) { for (i in length - 1 downTo 0) bits.add((value ushr i) and 1) }
        put(4, 4)
        put(bytes.size, if (ver < 10) 8 else 16)
        bytes.forEach { put(it, 8) }
        val capacity = dataCodewords(ver) * 8
        put(0, minOf(4, capacity - bits.size))
        put(0, (8 - bits.size % 8) % 8)
        var pad = 0xEC
        while (bits.size < capacity) {
            put(pad, 8)
            pad = pad xor 0xEC xor 0x11
        }
        val data = (0 until bits.size / 8).map { k -> (0 until 8).fold(0) { acc, b -> (acc shl 1) or bits[k * 8 + b] } }

        val numBlocks = ECC_BLOCKS[ver]
        val eccLen = ECC_PER_BLOCK[ver]
        val rawCodewords = rawModules(ver) / 8
        val numShort = numBlocks - rawCodewords % numBlocks
        val shortLen = rawCodewords / numBlocks
        val divisor = rsDivisor(eccLen)
        val blocks = ArrayList<List<Int>>()
        var offset = 0
        for (bi in 0 until numBlocks) {
            val dat = data.subList(offset, offset + shortLen - eccLen + (if (bi < numShort) 0 else 1)).toMutableList()
            offset += dat.size
            val ecc = rsRemainder(dat, divisor)
            if (bi < numShort) dat.add(0)
            blocks.add(dat + ecc)
        }
        val codewords = ArrayList<Int>()
        for (ci in blocks[0].indices) {
            blocks.forEachIndexed { j, block -> if (ci != shortLen - eccLen || j >= numShort) codewords.add(block[ci]) }
        }

        val size = ver * 4 + 17
        val modules = Array(size) { BooleanArray(size) }
        val fn = Array(size) { BooleanArray(size) }
        fun setFn(x: Int, y: Int, dark: Boolean) { modules[y][x] = dark; fn[y][x] = true }
        fun finder(cx: Int, cy: Int) {
            for (dy in -4..4) for (dx in -4..4) {
                val dist = maxOf(kotlin.math.abs(dx), kotlin.math.abs(dy))
                val xx = cx + dx
                val yy = cy + dy
                if (xx in 0 until size && yy in 0 until size) setFn(xx, yy, dist != 2 && dist != 4)
            }
        }
        fun alignment(cx: Int, cy: Int) {
            for (dy in -2..2) for (dx in -2..2) setFn(cx + dx, cy + dy, maxOf(kotlin.math.abs(dx), kotlin.math.abs(dy)) != 1)
        }
        fun formatBits(mask: Int) {
            val d = (0 shl 3) or mask // level M = 0b00
            var rem = d
            repeat(10) { rem = (rem shl 1) xor ((rem ushr 9) * 0x537) }
            val f = ((d shl 10) or rem) xor 0x5412
            fun bit(i: Int) = ((f ushr i) and 1) != 0
            for (i in 0..5) setFn(8, i, bit(i))
            setFn(8, 7, bit(6)); setFn(8, 8, bit(7)); setFn(7, 8, bit(8))
            for (i in 9 until 15) setFn(14 - i, 8, bit(i))
            for (i in 0 until 8) setFn(size - 1 - i, 8, bit(i))
            for (i in 8 until 15) setFn(8, size - 15 + i, bit(i))
            setFn(8, size - 8, true)
        }
        for (t in 0 until size) { setFn(6, t, t % 2 == 0); setFn(t, 6, t % 2 == 0) }
        finder(3, 3); finder(size - 4, 3); finder(3, size - 4)
        if (ver > 1) {
            val n = ver / 7 + 2
            val step = ((ver * 4 + 4 + (n * 2 - 2) - 1) / (n * 2 - 2)) * 2 // ceil((ver*4+4)/(n*2-2))*2
            val pos = mutableListOf(6)
            var p = size - 7
            while (pos.size < n) { pos.add(1, p); p -= step }
            for (ai in 0 until n) for (aj in 0 until n) {
                if (!((ai == 0 && aj == 0) || (ai == 0 && aj == n - 1) || (ai == n - 1 && aj == 0))) alignment(pos[ai], pos[aj])
            }
        }
        formatBits(0)
        if (ver >= 7) {
            var r = ver
            repeat(12) { r = (r shl 1) xor ((r ushr 11) * 0x1F25) }
            val vb = (ver shl 12) or r
            for (vi in 0 until 18) {
                val vbit = ((vb ushr vi) and 1) != 0
                val a = size - 11 + vi % 3
                val b = vi / 3
                setFn(a, b, vbit); setFn(b, a, vbit)
            }
        }
        var idx = 0
        var right = size - 1
        while (right >= 1) {
            if (right == 6) right = 5
            for (vert in 0 until size) for (jj in 0 until 2) {
                val x = right - jj
                val upward = ((right + 1) and 2) == 0
                val y = if (upward) size - 1 - vert else vert
                if (!fn[y][x] && idx < codewords.size * 8) {
                    modules[y][x] = ((codewords[idx ushr 3] ushr (7 - (idx and 7))) and 1) != 0
                    idx++
                }
            }
            right -= 2
        }
        fun applyMask(mask: Int) {
            for (my in 0 until size) for (mx in 0 until size) {
                val inv = when (mask) {
                    0 -> (mx + my) % 2 == 0
                    1 -> my % 2 == 0
                    2 -> mx % 3 == 0
                    3 -> (mx + my) % 3 == 0
                    4 -> (mx / 3 + my / 2) % 2 == 0
                    5 -> mx * my % 2 + mx * my % 3 == 0
                    6 -> (mx * my % 2 + mx * my % 3) % 2 == 0
                    else -> ((mx + my) % 2 + mx * my % 3) % 2 == 0
                }
                if (inv && !fn[my][mx]) modules[my][mx] = !modules[my][mx]
            }
        }
        fun addHistory(length: Int, h: IntArray) {
            var len = length
            if (h[0] == 0) len += size
            for (i in h.size - 1 downTo 1) h[i] = h[i - 1]
            h[0] = len
        }
        fun countPatterns(h: IntArray): Int {
            val c = h[1]
            val core = c > 0 && h[2] == c && h[3] == c * 3 && h[4] == c && h[5] == c
            return (if (core && h[0] >= c * 4 && h[6] >= c) 1 else 0) + (if (core && h[6] >= c * 4 && h[0] >= c) 1 else 0)
        }
        fun terminate(color: Boolean, length: Int, h: IntArray): Int {
            var len = length
            if (color) { addHistory(len, h); len = 0 }
            len += size
            addHistory(len, h)
            return countPatterns(h)
        }
        fun penalty(): Int {
            var score = 0
            for (pass in 0 until 2) {
                for (a in 0 until size) {
                    var color = false
                    var run = 0
                    val h = IntArray(7)
                    for (b in 0 until size) {
                        val m = if (pass == 0) modules[a][b] else modules[b][a]
                        if (m == color) {
                            run++
                            if (run == 5) score += 3 else if (run > 5) score++
                        } else {
                            addHistory(run, h)
                            if (!color) score += countPatterns(h) * 40
                            color = m
                            run = 1
                        }
                    }
                    score += terminate(color, run, h) * 40
                }
            }
            for (y in 0 until size - 1) for (x in 0 until size - 1) {
                val c = modules[y][x]
                if (c == modules[y][x + 1] && c == modules[y + 1][x] && c == modules[y + 1][x + 1]) score += 3
            }
            val dark = modules.sumOf { row -> row.count { it } }
            val total = size * size
            // ceil(|dark*20 - total*10| / total) - 1, in integers.
            val diff = kotlin.math.abs(dark * 20 - total * 10)
            score += ((diff + total - 1) / total - 1) * 10
            return score
        }
        var best = 0
        var bestScore = Int.MAX_VALUE
        for (mask in 0 until 8) {
            applyMask(mask)
            formatBits(mask)
            val s = penalty()
            if (s < bestScore) { best = mask; bestScore = s }
            applyMask(mask)
        }
        applyMask(best)
        formatBits(best)
        return modules
    }
}
