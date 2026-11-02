package com.viadere.sdk

/**
 * A small strict JSON reader and writer, so the library needs neither `org.json` (a stub in JVM unit tests) nor a third-party parser.
 *
 * Strict means: one value, no trailing bytes, no duplicate object keys, no control characters in strings, no leading zeros, nesting at most 32.
 * Objects become `Map<String, Any?>`, arrays `List<Any?>`, numbers `Long` (integers) or `Double`, plus `String`, `Boolean` and `null`.
 */
internal object StrictJson {
    class ParseException(message: String) : Exception(message)

    fun parse(text: String): Any? {
        val reader = Reader(text)
        reader.skipWhitespace()
        val value = reader.value(0)
        reader.skipWhitespace()
        if (!reader.atEnd) throw ParseException("trailing data")
        return value
    }

    private class Reader(private val s: String) {
        private var i = 0
        val atEnd: Boolean get() = i >= s.length

        fun skipWhitespace() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        fun value(depth: Int): Any? {
            if (depth > 32) throw ParseException("too deep")
            if (atEnd) throw ParseException("unexpected end")
            return when (val c = s[i]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') num() else throw ParseException("unexpected character")
            }
        }

        private fun literal(word: String, result: Any?): Any? {
            if (!s.startsWith(word, i)) throw ParseException("bad literal")
            i += word.length
            return result
        }

        private fun obj(depth: Int): Map<String, Any?> {
            i++ // {
            val out = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (peek() == '}') { i++; return out }
            while (true) {
                skipWhitespace()
                if (peek() != '"') throw ParseException("expected a key")
                val key = str()
                skipWhitespace()
                if (peek() != ':') throw ParseException("expected ':'")
                i++
                skipWhitespace()
                if (out.containsKey(key)) throw ParseException("duplicate key")
                out[key] = value(depth + 1)
                skipWhitespace()
                when (peek()) {
                    ',' -> i++
                    '}' -> { i++; return out }
                    else -> throw ParseException("expected ',' or '}'")
                }
            }
        }

        private fun arr(depth: Int): List<Any?> {
            i++ // [
            val out = ArrayList<Any?>()
            skipWhitespace()
            if (peek() == ']') { i++; return out }
            while (true) {
                skipWhitespace()
                out.add(value(depth + 1))
                skipWhitespace()
                when (peek()) {
                    ',' -> i++
                    ']' -> { i++; return out }
                    else -> throw ParseException("expected ',' or ']'")
                }
            }
        }

        private fun peek(): Char = if (i < s.length) s[i] else throw ParseException("unexpected end")

        private fun str(): String {
            i++ // opening quote
            val sb = StringBuilder()
            while (true) {
                if (atEnd) throw ParseException("unterminated string")
                val c = s[i++]
                when {
                    c == '"' -> return sb.toString()
                    c < ' ' -> throw ParseException("control character in string")
                    c == '\\' -> {
                        if (atEnd) throw ParseException("bad escape")
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> sb.append(e)
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (i + 4 > s.length) throw ParseException("bad escape")
                                val hex = s.substring(i, i + 4)
                                if (!hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) throw ParseException("bad escape")
                                sb.append(hex.toInt(16).toChar())
                                i += 4
                            }
                            else -> throw ParseException("bad escape")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun num(): Any {
            val start = i
            if (s[i] == '-') i++
            if (atEnd) throw ParseException("bad number")
            if (s[i] == '0') i++ else if (s[i] in '1'..'9') { while (!atEnd && s[i] in '0'..'9') i++ } else throw ParseException("bad number")
            var integral = true
            if (!atEnd && s[i] == '.') {
                integral = false
                i++
                val digits = i
                while (!atEnd && s[i] in '0'..'9') i++
                if (i == digits) throw ParseException("bad number")
            }
            if (!atEnd && (s[i] == 'e' || s[i] == 'E')) {
                integral = false
                i++
                if (!atEnd && (s[i] == '+' || s[i] == '-')) i++
                val digits = i
                while (!atEnd && s[i] in '0'..'9') i++
                if (i == digits) throw ParseException("bad number")
            }
            val text = s.substring(start, i)
            return if (integral) text.toLongOrNull() ?: text.toDouble() else text.toDouble()
        }
    }

    /** Serialises maps, lists, strings, numbers, booleans and null. Escapes everything JSON requires and every non-ASCII control character. */
    fun write(value: Any?): String = StringBuilder().also { append(it, value) }.toString()

    private fun append(sb: StringBuilder, value: Any?) {
        when (value) {
            null -> sb.append("null")
            is String -> quote(sb, value)
            is Boolean, is Int, is Long -> sb.append(value.toString())
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, v) in value) {
                    if (!first) sb.append(',')
                    first = false
                    quote(sb, k as String)
                    sb.append(':')
                    append(sb, v)
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                value.forEachIndexed { index, item ->
                    if (index > 0) sb.append(',')
                    append(sb, item)
                }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("unsupported JSON value")
        }
    }

    private fun quote(sb: StringBuilder, text: String) {
        sb.append('"')
        for (c in text) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' -> sb.append("\\u").append(c.code.toString(16).padStart(4, '0'))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }
}
