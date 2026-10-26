package com.example.countersign

import android.content.Intent
import android.os.Bundle
import android.util.Base64
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/** Enrollment and the device's pending requests, with automatic refresh while visible. */
class MainActivity : AppCompatActivity() {
    private val apiClient = ApiClient(AppConfig.BASE_URL)
    private lateinit var screen: HomeScreen
    private var pollingJob: Job? = null
    private var isEnrolling = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        ScreenUi.applyInsets(this)
        screen = HomeScreen(this)
        screen.enrollButton.setOnClickListener { enroll() }
        screen.refreshButton.setOnClickListener {
            DeviceState.getDeviceId(this)?.let { startPolling(it, showLoading = true) }
        }
    }

    override fun onResume() {
        super.onResume()
        if (isEnrolling) return
        val deviceId = DeviceState.getDeviceId(this)
        if (deviceId == null) {
            showNotEnrolled()
        } else {
            screen.setDeviceState("checking", deviceId)
            screen.refreshButton.isEnabled = true
            startPolling(deviceId, showLoading = true)
        }
    }

    override fun onPause() {
        pollingJob?.cancel()
        pollingJob = null
        super.onPause()
    }

    private fun showNotEnrolled(description: String? = null) {
        screen.setLoading(false)
        screen.setDeviceState("not_enrolled", description = description)
        screen.refreshButton.isEnabled = false
        screen.showEmpty(getString(R.string.no_pending_approvals))
    }

    private fun startPolling(deviceId: String, showLoading: Boolean = false) {
        pollingJob?.cancel()
        pollingJob = lifecycleScope.launch {
            if (showLoading) screen.setLoading(true)
            try {
                while (isActive) {
                    refreshPendingApprovals(deviceId)
                    screen.setLoading(false)
                    delay(3000)
                }
            } finally {
                screen.setLoading(false)
            }
        }
    }

    private fun enroll() {
        if (isEnrolling) return
        isEnrolling = true
        screen.setDeviceState("enrolling")
        screen.setLoading(true)
        screen.showEmpty(getString(R.string.no_pending_approvals))
        lifecycleScope.launch {
            try {
                val begin = apiClient.beginEnrollment()
                val enrollmentId = begin.getString("enrollment_id")
                val challengeB64 = begin.getString("challenge_b64")
                val challenge = Base64.decode(challengeB64, Base64.NO_WRAP)
                val chain = DeviceTrust.generateApprovalKey(challenge)
                val chainB64 = chain.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }
                val integrityToken = DeviceTrust.requestIntegrityToken(this@MainActivity, challengeB64)
                val result = apiClient.completeEnrollment(enrollmentId, chainB64, integrityToken)
                val deviceId = result.getString("device_id")
                DeviceState.saveDeviceId(this@MainActivity, deviceId)
                screen.setDeviceState(result.getString("status"), deviceId)
                screen.refreshButton.isEnabled = true
                if (lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) startPolling(deviceId)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                screen.setDeviceState("error", description = ScreenUi.connectionError(this@MainActivity, error))
                screen.showEmpty(getString(R.string.no_pending_approvals))
            } finally {
                isEnrolling = false
                screen.setLoading(false)
            }
        }
    }

    private suspend fun refreshPendingApprovals(deviceId: String) {
        try {
            val status = apiClient.enrollmentStatus(deviceId).getString("status")
            screen.setDeviceState(status, deviceId)
            if (status == "approved") {
                screen.showRequests(apiClient.listPendingApprovals(deviceId), ::openApproval)
            } else if (status == "pending_manual_approval") {
                screen.showEmpty(getString(R.string.no_pending_approvals))
            } else {
                screen.showEmpty(getString(R.string.requests_enrollment_unknown_title), getString(R.string.requests_enrollment_unknown_description), error = true)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: ApiException) {
            if (error.statusCode == 404) {
                DeviceState.clearDeviceId(this)
                showNotEnrolled(getString(R.string.device_missing_description))
                pollingJob?.cancel()
                pollingJob = null
            } else {
                showConnectionError(error)
            }
        } catch (error: Exception) {
            showConnectionError(error)
        }
    }

    private fun showConnectionError(error: Exception) {
        screen.setDeviceState("checking", DeviceState.getDeviceId(this))
        screen.showEmpty(getString(R.string.requests_refresh_failed), ScreenUi.connectionError(this@MainActivity, error), error = true, countLabel = getString(R.string.count_unavailable))
    }

    private fun openApproval(ref: String) {
        startActivity(Intent(this, ApprovalActivity::class.java).putExtra(ApprovalActivity.EXTRA_REF, ref))
    }
}
