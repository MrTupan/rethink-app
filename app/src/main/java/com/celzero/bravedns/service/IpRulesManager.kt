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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject

object IpRulesManager : KoinComponent {

    private val db by inject<CustomIpRepository>()

    // max size of ip request look-up cache
    private const val CACHE_MAX_SIZE = 10000L

    // separate tries are used internally for ip4 and ip6, if the implementation changes in the
    // future, ensure both cases continue to be handled correctly.
    private val iptree by lazy { Backend.newIpTree() }

    // Active connection concurrency tracker per rule (UID + Protocol)
    private val activeConnsMap = ConcurrentHashMap<String, AtomicInteger>()

    // key-value object for ip look-up
    data class CacheKey(val ipNetPort: String, val uid: Int, val protocol: String)

    // stores the response for the look-up request from the BraveVpnService
    // especially useful for storing results of subnetMatch() function as it is expensive
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

            // labels for spinner / toggle ui
            fun getLabel(context: Context): Array<String> {
                return arrayOf(
                    context.getString(R.string.ci_no_rule),
                    context.getString(R.string.ci_block),
                    context.getString(R.string.ci_trust_rule)
                )
            }

            fun getStatus(id: Int?): IpRuleStatus {
                if (id == null) {
                    return NONE
                }

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

    fun acquireConnection(uid: Int, protocol: String, limit: Int): Boolean {
        if (limit <= 0) return true
        val key = "$uid$KV_SEP${protocol.uppercase()}"
        val counter = activeConnsMap.computeIfAbsent(key) { AtomicInteger(0) }
        while (true) {
            val current = counter.get()
            if (current >= limit) {
                Logger.i(LOG_TAG_FIREWALL, "Connection limit reached for $key ($current >= $limit). Rejecting connection.")
                return false
            }
            if (counter.compareAndSet(current, current + 1)) {
                Logger.d(LOG_TAG_FIREWALL, "Acquired conn for $key. Active: ${current + 1}/$limit")
                return true
            }
        }
    }

    fun releaseConnection(uid: Int, protocol: String) {
        val key = "$uid$KV_SEP${protocol.uppercase()}"
        activeConnsMap[key]?.let {
            val count = it.decrementAndGet()
            if (count < 0) it.set(0)
            Logger.d(LOG_TAG_FIREWALL, "Released conn for $key. Active: $count")
        }
    }

    suspend fun load(): Long {
        try {
            iptree.clear()
            activeConnsMap.clear()
        } catch (e: Exception) {
            Logger.e(LOG_TAG_FIREWALL, "err iptree.clear()", e)
        }
        db.getIpRules().forEach {
            // adding as part of defensive programming, even adding these rules to cache will
            // not cause any issues, but to avoid unnecessary entries in the trie, skipping these
            // entries
            if (it.uid < 0 && it.uid != Constants.UID_EVERYBODY) {
                Logger.i(LOG_TAG_FIREWALL, "skipping ip rule for uid: ${it.uid}")
                return@forEach
            }
            val pair = it.getCustomIpAddress()
            if (pair == null) {
                Logger.w(LOG_TAG_FIREWALL, "invalid ip address for rule: ${it.ipAddress}")
                return@forEach
            }
            val ipaddr = pair.first
            val port = pair.second
            val k = normalize(ipaddr)
            val v = treeVal(it.uid, port, it.fromPort, it.toPort, it.protocol, it.connLimit, it.status, it.proxyId, it.proxyCC)
            if (k != null) {
                try {
                    Logger.vv(LOG_TAG_FIREWALL, "iptree.add($k, $v)")
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
            Logger.e(LOG_TAG_FIREWALL, "err iptree.len()", e)
            -1L
        }
        Logger.i(LOG_TAG_FIREWALL, "ip rules loaded, count: $count")
        return count.coerceAtLeast(0)
    }

    fun getAllUniqueCCs(): Set<String> {
        logv("ip selectedCCs: $selectedCCs")
        return selectedCCs
    }

    suspend fun getRulesCountByCC(cc: String): Int {
        return db.getRulesCountByCC(cc)
    }

    // Room's DAO returns a new LiveData instance on every call; cache it so
    // observers and value-reads share the same instance.
    private val cachedIpsCountLiveData: LiveData<Int> by lazy { db.getCustomIpsLiveData() }

    fun getCustomIpsLiveData(): LiveData<Int> {
        return cachedIpsCountLiveData
    }

    private fun normalize(ipaddr: IPAddress?): String? {
        if (ipaddr == null) return null
        return treeKey(ipaddr.toNormalizedString())
    }

    /**
     * Never throws: returns the CIDR key for the trie, or null when the input
     * cannot be enforced by the CIDR-only ip trie.
     */
    private fun treeKey(ipstr: String?): String? {
        if (ipstr == null) return null
        return try {
            treeKey0(ipstr)
        } catch (e: Exception) {
            Logger.w(LOG_TAG_FIREWALL, "err treeKey('$ipstr'); rule stored but not enforced, ${e.message}", e)
            null
        }
    }

    private fun treeKey0(ipstr: String): String? {
        val pair = hostAddr(ipstr)
        val ipAddr = pair.first
        return if (ipstr.contains("*")) {
            val singleBlock = ipAddr.assignPrefixForSingleBlock()
            if (singleBlock == null) {
                Logger.w(LOG_TAG_FIREWALL, "wildcard '$ipstr' has no single CIDR block; rule stored but not enforced")
            }
            singleBlock?.toCanonicalString()
        } else {
            if (!ipAddr.isMultiple) {
                ipAddr.toNormalizedString()
            } else {
                val singleBlock = try {
                    ipAddr.assignPrefixForSingleBlock()
                } catch (e: Exception) {
                    Logger.w(LOG_TAG_FIREWALL, "err converting range '$ipstr' to CIDR block", e)
                    null
                }
                if (singleBlock == null) {
                    Logger.w(LOG_TAG_FIREWALL, "ip range '$ipstr' has no single CIDR block; rule stored but not enforced")
                }
                singleBlock?.toCanonicalString()
            }
        }
    }

    private fun treeValLike(uid: Int, port: Int): String {
        return ("$uid$KV_SEP$port")
    }

    private fun treeValLike(uid: Int): String {
        return ("$uid$KV_SEP")
    }

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
        return ("$uid$KV_SEP$port$KV_SEP$fromPort$KV_SEP$toPort$KV_SEP${protocol.uppercase()}$KV_SEP$connLimit$KV_SEP$rule$KV_SEP$proxyId$KV_SEP$proxyCC")
    }

    suspend fun removeIpRule(uid: Int, ipstr: String, port: Int) {
        Logger.i(LOG_TAG_FIREWALL, "ip rule, rmv: $ipstr for uid: $uid")
        if (ipstr.isEmpty()) {
            return
        }

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
        // ensure modified time is updated for ordering
        ci.modifiedDateTime = System.currentTimeMillis()
        db.update(ci)
        val ipaddr = normalize(ci.getCustomIpAddress()?.first)
        val k = treeKey(ipaddr)
        Logger.i(LOG_TAG_FIREWALL, "ip rule, update: $ipaddr for uid: ${ci.uid}; status: ${ci.status}")

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

    fun hasRule(uid: Int, ipstr: String, port: Int, protocol: String = "ALL"): IpRuleStatus {
        val pair = hostAddr(ipstr, port)
        val ipNetPort = joinIpNetPort(normalize(pair.first) + pair.second)
        val ck = CacheKey(ipNetPort, uid, protocol.uppercase())

        resultsCache.getIfPresent(ck)?.let {
            logv("match in cache $uid $ipstr: $it")
            return it
        }

        // 1. Check Specific IP with Protocol
        getMostSpecificRuleMatch(uid, ipstr, port, protocol).let {
            logv("ip rule for $uid $ipstr $port => ${it.name}")
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }

        // 2. Check 0.0.0.0/0 Wildcard Range for this App
        getMostSpecificRuleMatch(uid, "0.0.0.0/0", port, protocol).let {
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }

        // 3. Check Universal Rules (UID_EVERYBODY)
        getMostSpecificRuleMatch(Constants.UID_EVERYBODY, "0.0.0.0/0", port, protocol).let {
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }

        // 4. Route matches fallback
        getMostSpecificRouteMatch(uid, ipstr, port, protocol).let {
            if (it != IpRuleStatus.NONE) {
                resultsCache.put(ck, it)
                return it
            }
        }

        Logger.i(LOG_TAG_FIREWALL, "hasRule? NO $uid, $ipstr, $port, $protocol")
        resultsCache.put(ck, IpRuleStatus.NONE)
        return IpRuleStatus.NONE
    }

    // Overload for backward compatibility
    fun hasRule(uid: Int, ipstr: String, port: Int): IpRuleStatus = hasRule(uid, ipstr, port, "ALL")

    fun hasProxy(uid: Int, ipstr: String, port: Int): Pair<String, String> {
        getMostSpecificMatchProxies(uid, ipstr, port).let {
            logv("proxy for $uid $ipstr $port => ${it.first}, ${it.second}")
            if (it.first.isNotEmpty() && it.second.isNotEmpty()) {
                return it
            }
        }
        getMostSpecificMatchProxies(uid, ipstr).let {
            logv("proxy for $uid $ipstr => ${it.first}, ${it.second}")
            if (it.first.isNotEmpty() && it.second.isNotEmpty()) {
                return it
            }
        }
        getMostSpecificRouteProxies(uid, ipstr, port).let {
            logv("route rule for $uid $ipstr $port => ${it.first}, ${it.second}")
            if (it.first.isNotEmpty() && it.second.isNotEmpty()) {
                return it
            }
        }
        getMostSpecificRouteProxies(uid, ipstr).let {
            logv("route rule for $uid $ipstr => ${it.first}, ${it.second}")
            if (it.first.isNotEmpty() && it.second.isNotEmpty()) {
                return it
            }
        }

        Logger.i(LOG_TAG_FIREWALL, "hasProxy? NO $uid, $ipstr, $port")
        return Pair("", "")
    }

    private fun hostAddr(ipstr: String, p: Int? = null): Pair<IPAddress, Int> {
        try {
            val ip: IPAddress? = IPAddressString(ipstr).address
            val port: Int = p ?: 0
            if (ip == null) {
                Logger.w(LOG_TAG_FIREWALL, "Invalid IP address; ip:port $ipstr:$port")
                return Pair(IPAddressString("0.0.0.0").address, 0)
            }
            return Pair(ip, port)
        } catch (e: Exception) {
            Logger.w(LOG_TAG_FIREWALL, "Invalid IP address; ip:port $ipstr:$p", e)
            return Pair(IPAddressString("0.0.0.0").address, 0)
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

    fun getMostSpecificRuleMatch(uid: Int, ipstr: String, port: Int = 0, protocol: String = "ALL"): IpRuleStatus {
        val k = treeKey(ipstr)
        if (!k.isNullOrEmpty()) {
            val status = checkTreeForPortAndProto(k, treeValLike(uid), uid, port, protocol)
            if (status != IpRuleStatus.NONE) return status

            val globalStatus = checkTreeForPortAndProto(k, treeValLike(Constants.UID_EVERYBODY), Constants.UID_EVERYBODY, port, protocol)
            if (globalStatus != IpRuleStatus.NONE) return globalStatus
        }
        return IpRuleStatus.NONE
    }

    // Overload for backward compatibility
    fun getMostSpecificRuleMatch(uid: Int, ipstr: String, port: Int = 0): IpRuleStatus = getMostSpecificRuleMatch(uid, ipstr, port, "ALL")

    private fun checkTreeForPortAndProto(k: String, vlike: String, targetUid: Int, port: Int, protocol: String): IpRuleStatus {
        val x = try {
            iptree.getLike(k, vlike) ?: iptree.valuesLike(k, vlike)
        } catch (e: Exception) {
            Logger.e(LOG_TAG_FIREWALL, "err iptree.getLike($k, $vlike) for uid: $targetUid", e)
            return IpRuleStatus.NONE
        }
        val treeValues = x?.split(Backend.Vsep) ?: return IpRuleStatus.NONE
        treeValues.reversed().forEach {
            val treeVal = convertStringToTreeVal(it) ?: return@forEach

            // 1. Strict Protocol Match
            val protoMatches = treeVal.protocol.equals("ALL", ignoreCase = true) ||
                    protocol.equals("ALL", ignoreCase = true) ||
                    treeVal.protocol.equals(protocol, ignoreCase = true)

            if (!protoMatches) return@forEach

            // 2. Strict Port & Port Range Match
            val portMatches = if (treeVal.fromPort != UNSPECIFIED_PORT && treeVal.toPort != UNSPECIFIED_PORT && treeVal.fromPort <= treeVal.toPort) {
                port in treeVal.fromPort..treeVal.toPort
            } else if (treeVal.port != UNSPECIFIED_PORT && treeVal.port != 0) {
                treeVal.port == port
            } else {
                true // Port 0 / unspecified matches any port
            }

            if ((treeVal.uid == targetUid || treeVal.uid == Constants.UID_EVERYBODY) && portMatches && treeVal.status != IpRuleStatus.NONE) {
                // 3. Concurrency Limit Check
                if (treeVal.status == IpRuleStatus.TRUST || treeVal.status == IpRuleStatus.BYPASS_UNIVERSAL) {
                    if (treeVal.connLimit > 0 && !acquireConnection(targetUid, protocol, treeVal.connLimit)) {
                        return IpRuleStatus.BLOCK
                    }
                }
                logv("found match for $targetUid:$port in rule [${treeVal.fromPort}-${treeVal.toPort}][${treeVal.protocol}] => ${treeVal.status}")
                return treeVal.status
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
            Logger.e(LOG_TAG_FIREWALL, "err converting string to TreeVal: $s, ${e.message}")
            return null
        }
    }

    fun getMostSpecificMatchProxies(uid: Int, ipstr: String, port: Int = 0): Pair<String, String> {
        val k = treeKey(ipstr)
        if (!k.isNullOrEmpty()) {
            val vlike = treeValLike(uid, port)
            val x = try {
                iptree.getLike(k, vlike)
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.getLike($k, $vlike) for uid: $uid", e)
                return Pair("", "")
            }
            if (DEBUG) logv("getMostSpecificRuleMatch: $uid, $k, $vlike => $x")
            val treeVals = x?.split(Backend.Vsep) ?: return Pair("", "")

            treeVals.reversed().forEach {
                val treeVal = convertStringToTreeVal(it)
                if (treeVal == null) {
                    logv("getMostSpecificMatchProxies: $uid, $k, $vlike => no match for $it")
                    return Pair("", "")
                }
                if (treeVal.uid == uid && treeVal.port == port) {
                    logv("getMostSpecificMatchProxies: $uid, $k, $vlike => found match for $it")
                    return Pair(treeVal.proxyId, treeVal.proxyCC)
                }
            }
        }
        return Pair("", "")
    }

    private fun getMostSpecificRouteMatch(uid: Int, ipstr: String, port: Int = 0, protocol: String = "ALL"): IpRuleStatus {
        return getMostSpecificRuleMatch(uid, ipstr, port, protocol)
    }

    private fun getMostSpecificRouteProxies(uid: Int, ipstr: String, port: Int = 0): Pair<String, String> {
        val k = treeKey(ipstr)
        if (!k.isNullOrEmpty()) {
            val vlike = treeValLike(uid, port)
            val x = try {
                iptree.valuesLike(k, vlike)
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.valuesLike($k, $vlike) for uid: $uid", e)
                return Pair("", "")
            }
            logv("getMostSpecificRouteMatch: $uid, $k, $vlike => $x")
            val treeVals = x?.split(Backend.Vsep) ?: return Pair("", "")
            treeVals.reversed().forEach {
                val treeVal = convertStringToTreeVal(it)
                if (treeVal == null) {
                    logv("getMostSpecificRouteProxies: $uid, $k, $vlike => no match for $it")
                    return Pair("", "")
                }
                if (treeVal.uid == uid && treeVal.port == port) {
                    logv("getMostSpecificRouteProxies: $uid, $k, $vlike => $it")
                    return Pair(treeVal.proxyId, treeVal.proxyCC)
                }
            }
        }
        return Pair("", "")
    }

    suspend fun deleteRulesByUid(uid: Int) {
        db.getRulesByUid(uid).forEach {
            val pair = it.getCustomIpAddress() ?: return@forEach
            val ipaddr = pair.first
            val port = pair.second
            val k = normalize(ipaddr)
            if (!k.isNullOrEmpty()) {
                try {
                    iptree.esc(k, treeVal(it.uid, port, it.fromPort, it.toPort, it.protocol, it.connLimit, it.status, it.proxyId, it.proxyCC))
                } catch (e: Exception) {
                    Logger.e(LOG_TAG_FIREWALL, "err iptree.esc($k) for uid: ${it.uid}", e)
                }
            }
        }
        db.deleteRulesByUid(uid)
        resultsCache.invalidateAll()
        Logger.i(LOG_TAG_FIREWALL, "deleted all ip rules for uid: $uid")
    }

    suspend fun deleteRules(list: List<CustomIp>) {
        list.forEach {
            val pair = it.getCustomIpAddress() ?: return@forEach
            val ipaddr = pair.first
            val port = pair.second
            val k = normalize(ipaddr)
            if (!k.isNullOrEmpty()) {
                try {
                    iptree.esc(k, treeVal(it.uid, port, it.fromPort, it.toPort, it.protocol, it.connLimit, it.status, it.proxyId, it.proxyCC))
                } catch (e: Exception) {
                    Logger.e(LOG_TAG_FIREWALL, "err iptree.esc($k) for uid: ${it.uid}", e)
                }
            }
        }
        db.deleteRules(list)
        resultsCache.invalidateAll()
    }

    suspend fun deleteAllAppsRules() {
        db.deleteAllAppsRules()
        try {
            iptree.clear()
        } catch (e: Exception) {
            Logger.e(LOG_TAG_FIREWALL, "err iptree.clear()", e)
        }
        resultsCache.invalidateAll()
    }

    suspend fun getObj(uid: Int, ipAddress: String, port: Int = 0): CustomIp? {
        return db.getCustomIpDetail(uid, ipAddress, port)
    }

    suspend fun isIpRuleExists(uid: Int, ipstr: IPAddress, port: Int = 0): Boolean {
        val normalizedIp = padAndNormalize(ipstr)
        return db.getCustomIpDetail(uid, normalizedIp, port) != null
    }

    suspend fun mkCustomIp(uid: Int, ipAddress: String, port: Int = UNSPECIFIED_PORT): CustomIp {
        return makeCustomIp(
            uid = uid,
            ipAddress = ipAddress,
            port = port,
            fromPort = UNSPECIFIED_PORT,
            toPort = UNSPECIFIED_PORT,
            protocol = "ALL",
            connLimit = 0,
            status = IpRuleStatus.NONE,
            wildcard = false,
            proxyId = "",
            proxyCC = ""
        )
    }

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
        customIp.protocol = protocol.uppercase()
        customIp.connLimit = connLimit
        customIp.isActive = true
        customIp.status = status.id
        customIp.wildcard = wildcard
        customIp.proxyId = proxyId
        customIp.proxyCC = proxyCC
        customIp.modifiedDateTime = System.currentTimeMillis()

        val ipaddr = customIp.getCustomIpAddress()?.first
        if (ipaddr == null) {
            Logger.w(LOG_TAG_FIREWALL, "Invalid IP address added")
            customIp.uid = uid
            customIp.ruleType = IPRuleType.IPV4.id
            return customIp
        }

        customIp.ruleType =
            if (ipaddr.isIPv6) {
                IPRuleType.IPV6.id
            } else {
                IPRuleType.IPV4.id
            }
        customIp.uid = uid
        return customIp
    }

    private fun padAndNormalize(ipaddr: IPAddress): String {
        var ipStr: String = ipaddr.toNormalizedString()
        try {
            if (ipaddr.isIPv4) {
                ipStr = padIpv4Cidr(ipaddr.toNormalizedString())
            }
            val pair = hostAddr(ipStr)
            return normalize(pair.first) ?: ipStr
        } catch (e: NullPointerException) {
            Logger.e(Logger.LOG_TAG_VPN, "Invalid IP address added", e)
        }
        return ""
    }

    private fun padIpv4Cidr(cidr: String): String {
        val ip = cidr.split(":")[0]
        val hasbraces = ip.contains("[") and ip.contains("]")
        val plaincidr = ip.replace("[", "").replace("]", "")
        val parts = plaincidr.split("/")
        val ipParts = parts[0].split(".").toMutableList()
        if (ipParts.size == 4) {
            return cidr
        }
        while (ipParts.size < 4) {
            ipParts.add("*")
        }
        for (i in (ipParts.size - 1) downTo 0) {
            if (ipParts[i] == "*") {
                continue
            } else if (ipParts[i] == "0") {
                ipParts[i] = "*"
            } else {
                break
            }
        }
        val paddedIp = ipParts.joinToString(".")
        if (parts.size == 1) return paddedIp
        return if (hasbraces) {
            "[$paddedIp/${parts[1]}]"
        } else {
            "$paddedIp/${parts[1]}"
        }
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
        Logger.i(
            LOG_TAG_FIREWALL,
            "ip rule, add range rule for ($uid) ip: $ipstr, ports: $fromPort-$toPort, proto: $protocol, limit: $connLimit with status: ${status.name}"
        )
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
                Logger.d(LOG_TAG_FIREWALL, "iptree.add($k, $tv)")
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.add($k) for uid: $uid", e)
            }
        }
        resultsCache.invalidateAll()
        return c
    }

    suspend fun updateUids(uids: List<Int>, newUids: List<Int>) {
        val ips = db.getIpRules()
        for (i in uids.indices) {
            val u = uids[i]
            val n = newUids[i]
            if (ips.any { it.uid == u }) {
                db.updateUid(u, n)
            }
        }
        resultsCache.invalidateAll()
        load()
        Logger.i(LOG_TAG_FIREWALL, "ip rules updated")
    }

    suspend fun updateUid(oldUid: Int, newUid: Int) {
        db.updateUid(oldUid, newUid)
        resultsCache.invalidateAll()
        load()
        Logger.i(LOG_TAG_FIREWALL, "ip rules updated for $oldUid to $newUid")
    }

    suspend fun replaceIpRule(
        prevRule: CustomIp,
        ipaddr: IPAddress,
        port: Int?,
        newStatus: IpRuleStatus,
        proxyId: String,
        proxyCC: String
    ) {
        val pair = prevRule.getCustomIpAddress()
        if (pair == null) {
            Logger.e(LOG_TAG_FIREWALL, "invalid IP address on replaceIpRule ${prevRule.ipAddress}, ${prevRule.port}")
            return
        }

        val prevIpaddr = pair.first
        val prevPort = pair.second
        val prevIpAddrStr = normalize(prevIpaddr) ?: prevRule.ipAddress
        val newIpAddrStr = padAndNormalize(ipaddr)
        Logger.i(
            LOG_TAG_FIREWALL,
            "ip rule, replace (${prevRule.uid}); ${prevIpAddrStr}:${prevPort}; new: $ipaddr:$port, ${newStatus.name}"
        )
        val isDeleted = db.deleteRule(prevRule.uid, prevIpAddrStr, prevRule.port)
        if (isDeleted == 0) {
            db.deleteRule(prevRule.uid, prevRule.ipAddress, prevRule.port)
        }
        val newRule = makeCustomIp(prevRule.uid, newIpAddrStr, port, prevRule.fromPort, prevRule.toPort, prevRule.protocol, prevRule.connLimit, newStatus, false, proxyId, proxyCC)
        db.insert(newRule)
        val pk = treeKey(prevIpAddrStr)
        if (!pk.isNullOrEmpty()) {
            try {
                iptree.escLike(pk, treeValLike(prevRule.uid, prevRule.port))
                iptree.escLike(pk, treeValLike(prevRule.uid))
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.escLike($pk) for uid: ${prevRule.uid}", e)
            }
        }
        val nk = treeKey(newIpAddrStr)
        if (!nk.isNullOrEmpty()) {
            try {
                iptree.escLike(nk, treeValLike(newRule.uid, port ?: 0))
                iptree.escLike(nk, treeValLike(newRule.uid))
                val ntv = treeVal(newRule.uid, port ?: 0, newRule.fromPort, newRule.toPort, newRule.protocol, newRule.connLimit, newStatus.id, proxyId, proxyCC)
                iptree.add(nk, ntv)
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.add($nk) for uid: ${newRule.uid}", e)
            }
        }
        resultsCache.invalidateAll()
    }

    class AddrError(val err: String, val addr: String) : Exception()

    fun addrErr(addr: String, why: String): Triple<String, String, Exception?> {
        return Triple("", "", AddrError(why, addr))
    }

    fun splitHostPort(hostport: String): Triple<String, String, Exception?> {
        val missingPort = "missing port in address"
        val tooManyColons = "too many colons in address"

        var host = ""
        var port = ""
        val err: Exception? = null
        var j = 0
        var k = 0

        val i = hostport.lastIndexOf(':')
        if (i < 0) {
            return addrErr(hostport, missingPort)
        }

        if (hostport[0] == '[') {
            val end = hostport.indexOf(']')
            if (end < 0) {
                return addrErr(hostport, "missing ']' in address")
            }
            when (end + 1) {
                hostport.length -> {
                    return addrErr(hostport, missingPort)
                }
                i -> {
                }
                else -> {
                    if (hostport[end + 1] == ':') {
                        return addrErr(hostport, tooManyColons)
                    }
                    return addrErr(hostport, missingPort)
                }
            }
            host = hostport.substring(1, end)
            j = 1
            k = end + 1
        } else {
            host = hostport.substring(0, i)
            if (host.contains(':')) {
                return addrErr(hostport, tooManyColons)
            }
        }
        if (hostport.substring(j).contains('[')) {
            return addrErr(hostport, "unexpected '[' in address")
        }
        if (hostport.substring(k).contains(']')) {
            return addrErr(hostport, "unexpected ']' in address")
        }

        port = hostport.substring(i + 1)
        return Triple(host, port, err)
    }

    fun isCidrEnforceable(ipaddr: IPAddress?): Boolean {
        if (ipaddr == null) return false
        return try {
            if (!ipaddr.isMultiple) return true
            ipaddr.assignPrefixForSingleBlock() != null
        } catch (e: Exception) {
            Logger.w(LOG_TAG_FIREWALL, "err isCidrEnforceable, ${e.message}", e)
            false
        }
    }

    fun getIpNetPort(inp: String): Pair<IPAddress?, Int> {
        val h = splitHostPort(inp)
        var ipNet: IPAddress? = null
        var port = 0
        if (h.first.isEmpty()) {
            try {
                val ips = IPAddressString(inp)
                ips.validate()
                ipNet = ips.address
            } catch (e: Exception) {
                Logger.w(LOG_TAG_FIREWALL, "err: getIpNetPort, ${e.message}", e)
            }
        } else {
            try {
                ipNet = IPAddressString(h.first).address
                port = h.second.toIntOrNull() ?: 0
            } catch (e: Exception) {
                Logger.w(LOG_TAG_FIREWALL, "err: getIpNetPort, ${e.message}", e)
            }
        }
        return Pair(ipNet, port)
    }

    suspend fun tombstoneRulesByUid(oldUid: Int) {
        Logger.i(LOG_TAG_FIREWALL, "tombstone rules for uid: $oldUid")
        val newUid = if (oldUid > 0) -1 * oldUid else oldUid
        if (newUid == oldUid) {
            Logger.w(LOG_TAG_FIREWALL, "tombstone: same uids, old: $oldUid, new: $newUid, no-op")
            return
        }
        db.tombstoneRulesByUid(oldUid, newUid)
        resultsCache.invalidateAll()
        load()
    }

    fun joinIpNetPort(ipNet: String, port: Int = 0): String {
        return if (ipNet.contains(":") || ipNet.contains("/")) {
            "[$ipNet]:$port"
        } else {
            "$ipNet:$port"
        }
    }

    suspend fun stats(): String {
        val sb = StringBuilder()
        val treeLen = try {
            iptree.len()
        } catch (e: Exception) {
            Logger.e(LOG_TAG_FIREWALL, "err iptree.len()", e)
            -1L
        }
        sb.append("   iptree len: $treeLen\n")
        sb.append("   db len: ${db.getRulesCount()}\n")

        return sb.toString()
    }

    suspend fun isPortRuleSetForIp(ipcsv: String, uid: Int): Boolean {
        return ipcsv.split(",").any { ip ->
            val ipaddr = getIpNetPort(ip).first ?: return@any false
            val normalized = normalize(ipaddr).orEmpty()
            if (normalized.isEmpty()) return@any false

            val res = try {
                iptree.valuesLike(normalized, treeValLike(uid))
            } catch (e: Exception) {
                Logger.e(LOG_TAG_FIREWALL, "err iptree.valuesLike($normalized) for uid: $uid", e)
                return@any false
            } ?: return@any false
            val reversed = res.split(Backend.Vsep).reversed()
            if (reversed.isEmpty()) return@any false

            var isAnyTrusted = false
            reversed.forEach {
                val a = convertStringToTreeVal(it)
                if (a?.port != 0 && (a?.status == IpRuleStatus.TRUST || a?.status == IpRuleStatus.BYPASS_UNIVERSAL)) {
                    isAnyTrusted = true
                }
            }
            if (!isAnyTrusted) Logger.vv(LOG_TAG_FIREWALL, "isPortRuleSetForIp: $ip, $uid => false")
            else Logger.i(LOG_TAG_FIREWALL, "isPortRuleSetForIp: $ip, $uid => true")

            return isAnyTrusted
        }
    }
}
