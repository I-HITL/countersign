package com.example.countersign

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import kotlinx.coroutines.tasks.await
import java.security.MessageDigest

/** Cached Play Integrity Standard token provider, used only by genuine builds. */
object IntegrityHelper {
    private var cachedProvider: StandardIntegrityTokenProvider? = null

    suspend fun warmUp(context: Context, cloudProjectNumber: Long): StandardIntegrityTokenProvider {
        cachedProvider?.let { return it }
        val manager = IntegrityManagerFactory.createStandard(context.applicationContext)
        val provider = manager.prepareIntegrityToken(
            PrepareIntegrityTokenRequest.builder()
                .setCloudProjectNumber(cloudProjectNumber)
                .build(),
        ).await()
        cachedProvider = provider
        return provider
    }

    /**
     * [requestHash] must equal what the server will independently recompute
     * (compute_request_hash in service/integrity.py) over the exact bytes
     * being attested -- the base64 enrollment challenge at enroll time, or
     * the rendered approval message at approval time. Binding it here is
     * what stops an old, possibly-stale token from being replayed against a
     * different request.
     */
    suspend fun requestToken(provider: StandardIntegrityTokenProvider, requestHash: String): String {
        val response = provider.request(
            StandardIntegrityTokenRequest.builder()
                .setRequestHash(requestHash)
                .build(),
        ).await()
        return response.token()
    }

    /**
     * Mirrors compute_request_hash in service/integrity.py exactly:
     * url-safe base64 (WITH padding, matching Python's urlsafe_b64encode
     * default) of the SHA-256 digest of [message]'s UTF-8 bytes.
     */
    fun computeRequestHash(message: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(message.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_WRAP)
    }
}
