package com.example.countersign

import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.time.Instant

/** Displays and signs the service's exact message; all decoration stays outside those bytes. */
class ApprovalActivity : AppCompatActivity() {
    private val apiClient = ApiClient(AppConfig.BASE_URL)
    private lateinit var messageText: TextView
    private lateinit var expiryText: TextView
    private lateinit var approveButton: Button
    private lateinit var declineButton: Button
    private lateinit var resultText: TextView
    private lateinit var loadingProgress: View
    private var approvalMessage: String? = null
    private var expiry: Instant? = null
    private var status = "loading"
    private var isWorking = false
    private var expiryLabelExpired = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_approval)
        ScreenUi.applyInsets(this)
        // Hide non-system overlay windows (API 31+) and drop touches delivered
        // while another window is drawn over this one.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) window.setHideOverlayWindows(true)
        window.decorView.rootView.filterTouchesWhenObscured = true
        findViewById<ImageButton>(R.id.backButton).setOnClickListener { finish() }
        messageText = findViewById(R.id.messageText)
        expiryText = findViewById(R.id.expiryText)
        expiryText.setText(R.string.request_expiry_loading)
        approveButton = findViewById(R.id.approveButton)
        declineButton = findViewById(R.id.declineButton)
        resultText = findViewById(R.id.resultText)
        loadingProgress = findViewById(R.id.loadingProgress)
        resultText.visibility = View.GONE
        approveButton.text = getString(R.string.approve)
        setWorking(true)

        val ref = intent.getStringExtra(EXTRA_REF)
        if (ref.isNullOrBlank()) {
            setWorking(false)
            messageText.text = getString(R.string.request_open_failed)
            showExpiry()
            showResult(getString(R.string.request_select_again), error = true)
            return
        }
        findViewById<TextView>(R.id.refText).text = getString(R.string.request_reference, ref)
        messageText.text = getString(R.string.request_loading)
        lifecycleScope.launch {
            try {
                val approval = apiClient.getApproval(ref)
                status = approval.getString("status")
                approvalMessage = approval.getString("message")
                // Do not trim, reformat, or reconstruct the signed display string.
                messageText.text = approvalMessage
                expiry = ScreenUi.parseExpiry(approval.optString("expires_at"))
                showExpiry(forceExpired = status == "expired")
                if (status != "pending") showFinalStatus(status)
                updateExpiry()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                status = "unavailable"
                messageText.text = getString(R.string.request_unavailable)
                showExpiry()
                showResult(ScreenUi.connectionError(this@ApprovalActivity, error), error = true)
            } finally {
                setWorking(false)
            }
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                while (isActive) {
                    delay(1000)
                    updateExpiry()
                }
            }
        }
        approveButton.setOnClickListener { onApproveClicked(ref) }
        declineButton.setOnClickListener { onDeclineClicked(ref) }
    }

    private fun isExpired() = expiry?.let { !it.isAfter(Instant.now()) } ?: false

    private fun showExpiry(forceExpired: Boolean = false) {
        expiryLabelExpired = forceExpired || isExpired()
        expiryText.text = ScreenUi.expiryLabel(this, expiry?.toString(), forceExpired)
        expiryText.setTextColor(ContextCompat.getColor(this,
            if (expiryLabelExpired) R.color.cs_error else R.color.cs_text_secondary))
    }

    private fun updateExpiry() {
        if (status == "pending" && isExpired()) {
            if (!expiryLabelExpired) showExpiry(forceExpired = true)
            // The timestamp is the single expiry notice; retain any operation error.
            updateActions()
        }
    }

    private fun updateActions() {
        val enabled = status == "pending" && !isExpired() && !isWorking
        approveButton.isEnabled = enabled
        declineButton.isEnabled = enabled
    }

    private fun setWorking(working: Boolean) {
        isWorking = working
        loadingProgress.visibility = if (working) View.VISIBLE else View.GONE
        updateActions()
    }

    private fun showResult(message: String, error: Boolean = false) {
        resultText.text = message
        resultText.visibility = View.VISIBLE
        resultText.setBackgroundResource(if (error) R.drawable.bg_status_error else R.drawable.bg_status)
        resultText.setTextColor(ContextCompat.getColor(this, if (error) R.color.cs_error else R.color.cs_primary))
    }

    private fun showFinalStatus(value: String) {
        when (value) {
            "approved" -> showResult(getString(R.string.request_approved))
            "declined" -> showResult(getString(R.string.request_declined))
            "expired" -> showExpiry(forceExpired = true)
            "rejected" -> showResult(getString(R.string.request_rejected), error = true)
            else -> showResult(getString(R.string.request_status_unavailable, value), error = true)
        }
    }

    private fun onDeclineClicked(ref: String) {
        if (status != "pending" || isExpired() || isWorking) return
        setWorking(true)
        resultText.visibility = View.GONE
        lifecycleScope.launch {
            try {
                status = apiClient.declineApproval(ref).getString("status")
                showFinalStatus(status)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                showResult(ScreenUi.connectionError(this@ApprovalActivity, error), error = true)
            } finally {
                setWorking(false)
            }
        }
    }

    private fun onApproveClicked(ref: String) {
        val message = approvalMessage ?: return
        if (status != "pending" || isExpired() || isWorking) return
        if (!hasWindowFocus()) {
            showResult(getString(R.string.approval_window_unfocused), error = true)
            return
        }
        resultText.visibility = View.GONE
        setWorking(true)
        val signature = try {
            KeystoreHelper.signatureForApproval()
        } catch (error: Exception) {
            showResult(getString(R.string.approval_key_unavailable, error.localizedMessage ?: getString(R.string.check_enrollment)), error = true)
            setWorking(false)
            return
        }
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (isExpired()) {
                    showResult(getString(R.string.request_expired_during_authentication), error = true)
                    setWorking(false)
                    return
                }
                val signedSignature = result.cryptoObject?.signature
                if (signedSignature == null) {
                    showResult(getString(R.string.authentication_no_key), error = true)
                    setWorking(false)
                    return
                }
                completeApproval(ref, message, signedSignature)
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errorCode == BiometricPrompt.ERROR_CANCELED
                showResult(if (cancelled) getString(R.string.approval_cancelled) else getString(R.string.authentication_failed, errString), error = !cancelled)
                setWorking(false)
                updateExpiry()
            }
            override fun onAuthenticationFailed() {
                Toast.makeText(this@ApprovalActivity, getString(R.string.biometric_not_recognized), Toast.LENGTH_SHORT).show()
            }
        }
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_prompt_title))
            .setSubtitle(message)
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(getString(R.string.cancel))
            .build()
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
    }

    private fun completeApproval(ref: String, message: String, signature: java.security.Signature) {
        lifecycleScope.launch {
            try {
                signature.update(message.toByteArray(Charsets.UTF_8))
                val signatureB64 = Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
                val integrityToken = DeviceTrust.requestIntegrityToken(this@ApprovalActivity, message)
                val result = apiClient.completeApproval(ref, signatureB64, integrityToken)
                status = result.getString("status")
                showFinalStatus(status)
                val reasons = result.optJSONArray("reasons")
                if (reasons != null && reasons.length() > 0) {
                    showResult(
                        getString(R.string.request_result_with_reasons, resultText.text,
                            (0 until reasons.length()).joinToString("\n") { reasons.getString(it) }),
                        error = true,
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                showResult(ScreenUi.connectionError(this@ApprovalActivity, error), error = true)
            } finally {
                setWorking(false)
                updateExpiry()
            }
        }
    }

    companion object {
        const val EXTRA_REF = "com.example.countersign.EXTRA_REF"
    }
}
