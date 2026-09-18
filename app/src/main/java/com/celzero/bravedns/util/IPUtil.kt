/*
 * Copyright 2023 RethinkDNS and its authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.celzero.bravedns.util

import com.celzero.bravedns.util.Logger.LOG_TAG_VPN
import com.celzero.bravedns.RethinkDnsApplication.Companion.DEBUG
import inet.ipaddr.IPAddress
import java.net.InetAddress
import java.net.UnknownHostException
import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.pow

class IPUtil {

    data class PortRange(val fromPort: Int, val toPort: Int)

    data class ParsedCustomRule(
        val ipAddress: String,
        val portRange: PortRange,
        val protocol: String, // "ALL", "TCP", "UDP"
        val connLimit: Int    // 0 = unlimited, 1, 2, etc.
    )

    companion object {
        // IPv6 address byte positions for embedded IPv4 addresses
        private const val IPV6_EMBEDDED_IPV4_BYTE_POSITION_12 = 12
        private const val IPV6_TEREDO_IPV4_BYTE_POSITION_4 = 4

        // IPv6 prefix-64 segment value (hex 64 = decimal 100)
        private const val IPV6_PREFIX_64_SEGMENT_VALUE = 100

        // IPv4 address constants
        private const val IPV4_ADDRESS_BITS = 32
        private const val IPV4_ADDRESS_BYTE_COUNT = 4
        private const val IPV4_BYTE_MASK = 0xFF
        private const val IPV4_ADDRESS_MASK = 0xFFFFFFFFL

        // Bit shift constants
        private const val BITS_PER_BYTE = 8

        fun isIpV6(ip: IPAddress): Boolean {
            return ip.isIPv6
        }

        fun parsePortOrRange(input: String): PortRange? {
            return try {
                if (input.contains("-")) {
                    val parts = input.split("-")
                    val start = parts[0].trim().toInt()
                    val end = parts[1].trim().toInt()
                    if (start in 0..65535 && end in 0..65535 && start <= end) {
                        PortRange(start, end)
                    } else {
                        null
                    }
                } else {
                    val port = input.trim().toInt()
                    if (port in 0..65535) {
                        PortRange(port, port)
                    } else {
                        null
                    }
                }
            } catch (e: Exception) {
                null
            }
        }

        fun ip4in6(ip: IPAddress): IPAddress? {
            if (ip.isIPv4) {
                return null
            }
            if (isIpV4Compatible(ip)) {
                return ip.toIPv4()
            }

            if (isIpv6Prefix64(ip)) {
                return ip.toIPv6().getEmbeddedIPv4Address(IPV6_EMBEDDED_IPV4_BYTE_POSITION_12)
            }

            if (isIpTeredo(ip)) {
                return ip.toIPv6().getEmbeddedIPv4Address(IPV6_TEREDO_IPV4_BYTE_POSITION_4)
            }

            return null
        }

        private fun isIpV4Compatible(ip: IPAddress): Boolean {
            return ip.isIPv6 && ip.isIPv4Convertible && ip.toIPv4() != null
        }

        private fun isIpTeredo(ips: IPAddress): Boolean {
            return ips.toIPv6().isTeredo
        }

        private fun isIpv6Prefix64(ip: IPAddress): Boolean {
            val ipv6 = ip.toIPv6()
            val segment = ipv6.getSegment(0)
            return segment.segmentValue == IPV6_PREFIX_64_SEGMENT_VALUE
        }

        @Throws(UnknownHostException::class)
        fun toCIDR(start: InetAddress?, end: InetAddress?): List<CIDR>? {
            if (start == null || end == null) return null

            val listResult: MutableList<CIDR> = ArrayList()
            Logger.d(LOG_TAG_VPN, "toCIDR(" + start.hostAddress + "," + end.hostAddress + ")")
            var from: Long = inet2long(start)
            val to: Long = inet2long(end)
            while (to >= from) {
                var prefix: Byte = IPV4_ADDRESS_BITS.toByte()
                while (prefix > 0) {
                    val mask: Long = prefix2mask(prefix - 1)
                    if (from and mask != from) break
                    prefix--
                }
                val max = (IPV4_ADDRESS_BITS - floor(ln((to - from + 1).toDouble()) / ln(2.0))).toInt().toByte()
                if (prefix < max) prefix = max
                listResult.add(CIDR(long2inet(from)?.hostAddress, prefix.toInt()))
                from += 2.0.pow((IPV4_ADDRESS_BITS - prefix).toDouble()).toLong()
            }
            if (DEBUG) {
                for (cidr in listResult) Logger.d(LOG_TAG_VPN, cidr.toString())
            }
            return listResult
        }

        private fun prefix2mask(bits: Int): Long {
            return -0x100000000L shr bits and IPV4_ADDRESS_MASK
        }

        private fun inet2long(address: InetAddress?): Long {
            var result: Long = 0
            if (address != null)
                for (b in address.address) result = result shl BITS_PER_BYTE or (b.toInt() and IPV4_BYTE_MASK).toLong()
            return result
        }

        private fun long2inet(a: Long): InetAddress? {
            var addr = a
            return try {
                val b = ByteArray(IPV4_ADDRESS_BYTE_COUNT)
                for (i in b.indices.reversed()) {
                    b[i] = (addr and IPV4_BYTE_MASK.toLong()).toByte()
                    addr = addr shr BITS_PER_BYTE
                }
                InetAddress.getByAddress(b)
            } catch (ignore: UnknownHostException) {
                null
            }
        }

        fun minus1(address: InetAddress?): InetAddress? {
            return long2inet(inet2long(address) - 1)
        }

        fun plus1(address: InetAddress?): InetAddress? {
            return long2inet(inet2long(address) + 1)
        }
    }

    class CIDR : Comparable<CIDR?> {
        var address: InetAddress? = null
        var prefix = 0

        constructor(address: InetAddress?, prefix: Int) {
            this.address = address
            this.prefix = prefix
        }

        constructor(ip: String?, prefix: Int) {
            try {
                address = InetAddress.getByName(ip)
                this.prefix = prefix
            } catch (ex: UnknownHostException) {
                Logger.e(LOG_TAG_VPN, "error parsing CIDR, $ip, $prefix, $ex")
            }
        }

        val start: InetAddress?
            get() = long2inet(inet2long(address) and prefix2mask(prefix))

        val end: InetAddress?
            get() =
                long2inet((inet2long(address) and prefix2mask(prefix)) + (1L shl IPV4_ADDRESS_BITS - prefix) - 1)

        override fun toString(): String {
            return address?.hostAddress +
                "/" +
                prefix +
                "=" +
                start?.hostAddress +
                "..." +
                end?.hostAddress
        }

        override operator fun compareTo(other: CIDR?): Int {
            val lcidr = inet2long(address)
            val lother = inet2long(other?.address)
            return lcidr.compareTo(lother)
        }
    }
}
