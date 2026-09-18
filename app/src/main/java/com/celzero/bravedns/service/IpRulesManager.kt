/*
 * Copyright 2020 RethinkDNS and its authors
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
package com.celzero.bravedns.service

import com.celzero.bravedns.util.Logger
import com.celzero.bravedns.util.Logger.LOG_TAG_FIREWALL
import android.content.Context
import androidx.lifecycle.LiveData
import com.celzero.bravedns.R
import com.celzero.bravedns.RethinkDnsApplication.Companion.DEBUG
import com.celzero.bravedns.database.CustomIp
import com.celzero.bravedns.database.CustomIpRepository
import com.celzero.bravedns.util.Constants
import com.celzero.bravedns.util.Constants.Companion.UNSPECIFIED_PORT
import com.celzero.firestack.backend.Backend
import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import inet.ipaddr.IPAddress
import inet.ipaddr.IPAddressString
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

object IpRulesManager : KoinComponent {

    private val db by inject<CustomIpRepository>()

    private const val CACHE_MAX_SIZE = 10000L

    private val iptree by lazy { Backend.newIpTree() }

    data class CacheKey(val ipNetPort: String, val uid: Int)

    private val resultsCache: Cache<CacheKey, IpRuleStatus> =
        CacheBuilder.newBuilder().maximumSize(CACHE_MAX_SIZE).build()

    private val selectedCCs = mutableSetOf<String>()

    enum class IPRuleType(val id: Int) {
        IPV4(0),
        IPV6(2)
    }

    private const val KV_SEP = ":"

    enum class IpRuleStatus(val id: Int) {
        NONE(0),
        BLOCK(1),
        TRUST(2),
        BYPASS_UNIVERSAL(3);

        fun isBlocked(): Boolean {
            return this.id == BLOCK.id
        }

        companion object {
            fun getLabel(context: Context): Array<String> {
                return arrayOf(
                    context.getString(R.string.ci_no_rule),
                    context.getString(R.string.ci_block),
                    context.getString(R.string.ci_trust_rule)
                )
            }

            fun getStatus(id: Int?): IpRuleStatus {
                if (id == null) return NONE
                return when (id) {
                    NONE.id -> NONE
                    BLOCK.id -> BLOCK
                    TRUST.id -> TRUST
                    BYPASS_UNIVERSAL.id -> BYPASS_UNIVERSAL
                    else -> NONE
                }
            }
        }
    }

    private fun logv(msg: String) {
        Logger.v(LOG_TAG_FIREWALL, msg)
    }

    suspend fun load(): Long {
        try {
            iptree.clear()
        } catch (e: Exception) {
            Logger.e(LOG_TAG_FIREWALL, "err iptree.clear()", e)
        }
        db.getIpRules().forEach {
            if (it.uid < 0 && it.uid != Constants.UID_EVERYBODY) {
                return@forEach
            }
            val pair = it.getCustomIpAddress()
            if (pair == null) {
                return@forEach
            }
            val ipaddr = pair.first
            val port = pair.second
            val k = normalize(ipaddr)
            val v = treeVal(it.uid, port, it.fromPort, it.toPort, it.protocol, it.connLimit, it.status, it.proxyId, it.proxyCC)
            if (k != null) {
                try {
                    iptree.add(k, v)
                    if (it.proxyCC.isNotEmpty()) selectedCCs.add(it.proxyCC)
                } catch (e: Exception) {
                    Logger.e(LOG_TAG_FIREWALL, "err iptree.add($k, $v)", e)
                }
            }
        }
        val count = try {
            iptree.len()
        } catch (e: Exception) {
            -1L
        }
        Logger.i(LOG_TAG_FIREWALL, "ip rules loaded, count: $count")
        return count.coerceAtLeast(0)
    }

    fun getAllUniqueCCs(): Set<String> = selectedCCs

    suspend fun getRulesCountByCC(cc: String): Int = db.getRulesCountByCC(cc)

    private val cachedIpsCountLiveData: LiveData<Int> by lazy { db.getCustomIpsLiveData() }

    fun getCustomIpsLiveData(): LiveData<Int> = cachedIpsCountLiveData

    private fun normalize(ipaddr: IPAddress?): String? {
        if (ipaddr == null) return null
        return treeKey(ipaddr.toNormalizedString())
    }

    private fun treeKey(ipstr: String?): String? {
        if (ipstr == null) return null
        return try {
            treeKey0(ipstr)
        } catch (e: Exception) {
            null
        }
    }

    private fun treeKey0(ipstr: String): String? {
        val pair = hostAddr(ipstr)
        val ipAddr = pair.first
        return if (ipstr.contains("*")) {
            val singleBlock = ipAddr.assignPrefixForSingleBlock()
            singleBlock?.toCanonicalString()
        } else {
            if (!ipAddr.isMultiple) {
                ipAddr.toNormalizedString()
            } else {
                val singleBlock = try {
                    ipAddr.assignPrefixForSingleBlock()
                } catch (e: Exception) {
                    null
                }
                singleBlock?.toCanonicalString()
            }
        }
    }

    private fun treeValLike(uid: Int, port: Int): String = "$uid$KV_SEP$port"
    private fun treeValLike(uid: Int): String = "$uid$KV_SEP"

    private fun treeVal(
        uid: Int,
        port: Int,
        fromPort: Int = UNSPECIFIED_PORT,
        toPort: Int = UNSPECIFIED_PORT,
        protocol: String = "ALL",
        connLimit: Int = 0,
        rule: Int,
        proxyId: String,
        proxyCC: String
    ): String? {
        return "$uid$KV_SEP$port$KV_SEP$fromPort$KV_SEP$toPort$KV_SEP$protocol$KV_SEP$connLimit$KV_SEP$rule$KV_SEP$proxyId$KV_SEP$proxyCC"
    }

    suspend fun removeIpRule(uid: Int, ipstr: String, port: Int) {
        if (ipstr.isEmpty()) return
        db.deleteRule(uid, ipstr, port)
        val k = treeKey(ipstr)
        if (!k.isNullOrEmpty()) {
            try {
                iptree.escLike(k, treeValLike(uid, port))
                iptree.escLike(k, treeValLike(uid))
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.escLike($k) for uid: $uid", e)
            }
        }
        resultsCache.invalidateAll()
    }

    private suspend fun updateRule(ci: CustomIp) {
        ci.modifiedDateTime = System.currentTimeMillis()
        db.update(ci)
        val ipaddr = normalize(ci.getCustomIpAddress()?.first)
        val k = treeKey(ipaddr)

        if (!k.isNullOrEmpty()) {
            try {
                iptree.escLike(k, treeValLike(ci.uid, ci.port))
                iptree.escLike(k, treeValLike(ci.uid))
                iptree.add(k, treeVal(ci.uid, ci.port, ci.fromPort, ci.toPort, ci.protocol, ci.connLimit, ci.status, ci.proxyId, ci.proxyCC))
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.add($k) for uid: ${ci.uid}", e)
            }
        }
        resultsCache.invalidateAll()
    }

    suspend fun updateBypass(c: CustomIp) {
        c.status = IpRuleStatus.BYPASS_UNIVERSAL.id
        return updateRule(c)
    }

    suspend fun updateTrust(c: CustomIp) {
        c.status = IpRuleStatus.TRUST.id
        return updateRule(c)
    }

    suspend fun updateNoRule(c: CustomIp) {
        c.status = IpRuleStatus.NONE.id
        return updateRule(c)
    }

    suspend fun updateBlock(c: CustomIp) {
        c.status = IpRuleStatus.BLOCK.id
        return updateRule(c)
    }

    suspend fun updateProxyId(c: CustomIp, proxyId: String) {
        c.proxyId = proxyId
        return updateRule(c)
    }

    suspend fun updateProxyCC(c: CustomIp, proxyCC: String) {
        c.proxyCC = proxyCC
        return updateRule(c)
    }

    fun hasRule(uid: Int, ipstr: String, port: Int): IpRuleStatus {
        val pair = hostAddr(ipstr, port)
        val ipNetPort = joinIpNetPort(normalize(pair.first) + pair.second)
        val ck = CacheKey(ipNetPort, uid)

        resultsCache.getIfPresent(ck)?.let {
            return it
        }

        // 1. Direct App Check (Exact Port + Range on specific IP)
        getMostSpecificRuleMatch(uid, ipstr, port).let {
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }

        // 2. Wildcard IPv4 (0.0.0.0/0) Check for this app (Evaluates 10000-65535 range!)
        getMostSpecificRuleMatch(uid, "0.0.0.0/0", port).let {
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }

        // 3. Wildcard IPv6 (::/0) Check for this app
        getMostSpecificRuleMatch(uid, "::/0", port).let {
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }

        // 4. Global Universal Rules (UID_EVERYBODY)
        getMostSpecificRuleMatch(Constants.UID_EVERYBODY, ipstr, port).let {
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }
        getMostSpecificRuleMatch(Constants.UID_EVERYBODY, "0.0.0.0/0", port).let {
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }

        resultsCache.put(ck, IpRuleStatus.NONE)
        return IpRuleStatus.NONE
    }

    fun getMostSpecificRuleMatch(uid: Int, ipstr: String, port: Int = 0): IpRuleStatus {
        val k = treeKey(ipstr)
        if (!k.isNullOrEmpty()) {
            // Check exact match and range matches in trie
            val x = try {
                iptree.getLike(k, treeValLike(uid)) ?: iptree.valuesLike(k, treeValLike(uid))
            } catch (e: Exception) {
                null
            } ?: return IpRuleStatus.NONE

            val treeValues = x.split(Backend.Vsep)
            treeValues.reversed().forEach {
                val treeVal = convertStringToTreeVal(it) ?: return@forEach
                
                val portMatches = if (treeVal.fromPort != UNSPECIFIED_PORT && treeVal.toPort != UNSPECIFIED_PORT && treeVal.fromPort <= treeVal.toPort) {
                    port in treeVal.fromPort..treeVal.toPort
                } else if (treeVal.port != UNSPECIFIED_PORT && treeVal.port != 0) {
                    treeVal.port == port
                } else {
                    true
                }

                if ((treeVal.uid == uid || treeVal.uid == Constants.UID_EVERYBODY) && portMatches && treeVal.status != IpRuleStatus.NONE) {
                    return treeVal.status
                }
            }
        }
        return IpRuleStatus.NONE
    }

    private fun convertStringToTreeVal(s: String): TreeVal? {
        try {
            val items = s.split(KV_SEP)
            if (items.size == 3) {
                val uid = items[0].toIntOrNull() ?: 0
                val port = items[1].toIntOrNull() ?: 0
                val status = IpRuleStatus.getStatus(items[2].toIntOrNull())
                return TreeVal(uid, port, UNSPECIFIED_PORT, UNSPECIFIED_PORT, "ALL", 0, status, "", "")
            }
            if (items.size == 5) {
                val uid = items[0].toIntOrNull() ?: 0
                val port = items[1].toIntOrNull() ?: 0
                val status = IpRuleStatus.getStatus(items[2].toIntOrNull())
                val proxyId = items[3]
                val proxyCC = items[4]
                return TreeVal(uid, port, UNSPECIFIED_PORT, UNSPECIFIED_PORT, "ALL", 0, status, proxyId, proxyCC)
            }
            if (items.size == 9) {
                val uid = items[0].toIntOrNull() ?: 0
                val port = items[1].toIntOrNull() ?: 0
                val fromPort = items[2].toIntOrNull() ?: UNSPECIFIED_PORT
                val toPort = items[3].toIntOrNull() ?: UNSPECIFIED_PORT
                val protocol = items[4]
                val connLimit = items[5].toIntOrNull() ?: 0
                val status = IpRuleStatus.getStatus(items[6].toIntOrNull())
                val proxyId = items[7]
                val proxyCC = items[8]
                return TreeVal(uid, port, fromPort, toPort, protocol, connLimit, status, proxyId, proxyCC)
            }
            return null
        } catch (e: Exception) {
            return null
        }
    }

    data class TreeVal(
        val uid: Int,
        val port: Int,
        val fromPort: Int,
        val toPort: Int,
        val protocol: String,
        val connLimit: Int,
        val status: IpRuleStatus,
        val proxyId: String,
        val proxyCC: String
    )

    private fun hostAddr(ipstr: String, p: Int? = null): Pair<IPAddress, Int> {
        try {
            val ip: IPAddress? = IPAddressString(ipstr).address
            val port: Int = p ?: 0
            if (ip == null) {
                return Pair(IPAddressString("0.0.0.0").address, 0)
            }
            return Pair(ip, port)
        } catch (e: Exception) {
            return Pair(IPAddressString("0.0.0.0").address, 0)
        }
    }

    fun hasProxy(uid: Int, ipstr: String, port: Int): Pair<String, String> = Pair("", "")
    suspend fun deleteRulesByUid(uid: Int) = db.deleteRulesByUid(uid)
    suspend fun deleteRules(list: List<CustomIp>) = db.deleteRules(list)
    suspend fun deleteAllAppsRules() = db.deleteAllAppsRules()
    suspend fun getObj(uid: Int, ipAddress: String, port: Int = 0): CustomIp? = db.getCustomIpDetail(uid, ipAddress, port)
    suspend fun isIpRuleExists(uid: Int, ipstr: IPAddress, port: Int = 0): Boolean = db.getCustomIpDetail(uid, padAndNormalize(ipstr), port) != null

    private fun makeCustomIp(
        uid: Int,
        ipAddress: String,
        port: Int?,
        fromPort: Int = UNSPECIFIED_PORT,
        toPort: Int = UNSPECIFIED_PORT,
        protocol: String = "ALL",
        connLimit: Int = 0,
        status: IpRuleStatus,
        wildcard: Boolean = false,
        proxyId: String,
        proxyCC: String
    ): CustomIp {
        val customIp = CustomIp()
        customIp.ipAddress = ipAddress
        customIp.port = port ?: UNSPECIFIED_PORT
        customIp.fromPort = fromPort
        customIp.toPort = toPort
        customIp.protocol = protocol
        customIp.connLimit = connLimit
        customIp.isActive = true
        customIp.status = status.id
        customIp.wildcard = wildcard
        customIp.proxyId = proxyId
        customIp.proxyCC = proxyCC
        customIp.modifiedDateTime = System.currentTimeMillis()
        customIp.uid = uid
        return customIp
    }

    private fun padAndNormalize(ipaddr: IPAddress): String {
        return normalize(ipaddr) ?: ipaddr.toNormalizedString()
    }

    suspend fun addIpRule(uid: Int, ipstr: IPAddress, port: Int?, status: IpRuleStatus, proxyId: String, proxyCC: String): CustomIp {
        return addIpRuleWithRange(uid, ipstr, port ?: 0, port ?: 0, "ALL", 0, status, proxyId, proxyCC)
    }

    suspend fun addIpRuleWithRange(
        uid: Int,
        ipstr: IPAddress,
        fromPort: Int,
        toPort: Int,
        protocol: String,
        connLimit: Int,
        status: IpRuleStatus,
        proxyId: String,
        proxyCC: String
    ): CustomIp {
        val normalizedIp = padAndNormalize(ipstr)
        val port = if (fromPort == toPort && fromPort != UNSPECIFIED_PORT) fromPort else 0
        val c = makeCustomIp(uid, normalizedIp, port, fromPort, toPort, protocol, connLimit, status, false, proxyId, proxyCC)
        db.insert(c)
        val k = treeKey(normalizedIp)
        if (!k.isNullOrEmpty()) {
            try {
                iptree.escLike(k, treeValLike(uid, port))
                iptree.escLike(k, treeValLike(uid))
                val tv = treeVal(uid, port, fromPort, toPort, protocol, connLimit, status.id, proxyId, proxyCC)
                iptree.add(k, tv)
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.add($k) for uid: $uid", e)
            }
        }
        resultsCache.invalidateAll()
        return c
    }

    fun isCidrEnforceable(ipaddr: IPAddress?): Boolean = true
    fun getIpNetPort(inp: String): Pair<IPAddress?, Int> {
        return try {
            val ips = IPAddressString(inp)
            Pair(ips.address, 0)
        } catch (e: Exception) {
            Pair(null, 0)
        }
    }

    fun joinIpNetPort(ipNet: String, port: Int = 0): String = "$ipNet:$port"
}
