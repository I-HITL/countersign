package com.example.countersign

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Minimal client for the Countersign service (see service/app.py). The API
 * surface is small enough that java.net.HttpURLConnection + org.json (both
 * built into Android) keep this self-contained -- no OkHttp/Retrofit/Gson.
 */
class ApiClient(
    private val baseUrl: String,
    private val token: String = AppConfig.DEVICE_API_TOKEN,
) {

    suspend fun beginEnrollment(): JSONObject {
        check(baseUrl.isNotBlank() && token.isNotBlank()) {
            "Configure the backend URL and device token in deployment.properties and rebuild the app."
        }
        return post("/v1/enroll/begin", JSONObject().apply { put("platform", "android") })
    }

    suspend fun completeEnrollment(
        enrollmentId: String,
        attestationChainDerB64: List<String>,
        integrityToken: String,
    ): JSONObject {
        val body = JSONObject().apply {
            put("attestation_chain_der_b64", JSONArray(attestationChainDerB64))
            put("integrity_token", integrityToken)
        }
        return post("/v1/enroll/$enrollmentId/complete", body)
    }

    suspend fun enrollmentStatus(deviceId: String): JSONObject =
        get("/v1/enrollments/${URLEncoder.encode(deviceId, "UTF-8")}")

    suspend fun getApproval(ref: String): JSONObject = get("/v1/approvals/$ref")

    suspend fun listPendingApprovals(deviceId: String): JSONArray {
        val encoded = URLEncoder.encode(deviceId, "UTF-8")
        return getArray("/v1/approvals?device_id=$encoded")
    }

    suspend fun completeApproval(ref: String, signatureB64: String, integrityToken: String): JSONObject {
        val body = JSONObject().apply {
            put("signature_b64", signatureB64)
            put("integrity_token", integrityToken)
        }
        return post("/v1/approvals/$ref/complete", body)
    }

    suspend fun declineApproval(ref: String): JSONObject = post("/v1/approvals/$ref/decline", JSONObject())

    private suspend fun get(path: String): JSONObject = JSONObject(request("GET", path))

    private suspend fun getArray(path: String): JSONArray = JSONArray(request("GET", path))

    private suspend fun post(path: String, body: JSONObject): JSONObject =
        JSONObject(request("POST", path, body))

    private suspend fun request(method: String, path: String, body: JSONObject? = null): String =
        withContext(Dispatchers.IO) {
            val connection = URL(baseUrl + path).openConnection() as HttpURLConnection
            try {
                connection.requestMethod = method
                authenticate(connection)
                if (body != null) {
                    connection.doOutput = true
                    connection.setRequestProperty("Content-Type", "application/json")
                    OutputStreamWriter(connection.outputStream, Charsets.UTF_8).use { it.write(body.toString()) }
                }
                val code = connection.responseCode
                val stream = if (code in 200..299) connection.inputStream else connection.errorStream
                val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
                if (code !in 200..299) throw ApiException(code, text)
                text
            } finally {
                connection.disconnect()
            }
        }

    private fun authenticate(connection: HttpURLConnection) {
        connection.connectTimeout = 10_000
        connection.readTimeout = 15_000
        connection.setRequestProperty("Authorization", "Bearer $token")
        // A non-browser user agent keeps tunneling proxies from serving an HTML interstitial.
        connection.setRequestProperty("User-Agent", "Countersign/${BuildConfig.VERSION_NAME}")
    }
}

class ApiException(val statusCode: Int, val body: String) : Exception("HTTP $statusCode: $body")
