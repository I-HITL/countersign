package com.example.countersign

import android.content.Context
import android.graphics.Color
import android.view.View
import android.widget.Button
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import org.json.JSONArray
import java.time.Instant
import java.text.DateFormat
import java.text.NumberFormat
import java.util.Date

/** Shared presentation for enrollment and live approval requests. */
internal object ScreenUi {
    fun applyInsets(activity: AppCompatActivity) {
        val root = activity.findViewById<View>(R.id.screenRoot)
        WindowCompat.setDecorFitsSystemWindows(activity.window, false)
        @Suppress("DEPRECATION")
        activity.window.apply {
            statusBarColor = Color.TRANSPARENT
            navigationBarColor = Color.TRANSPARENT
        }
        WindowInsetsControllerCompat(activity.window, root).apply {
            isAppearanceLightStatusBars = true
            isAppearanceLightNavigationBars = true
        }
        val left = root.paddingLeft
        val top = root.paddingTop
        val right = root.paddingRight
        val bottom = root.paddingBottom
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout())
            view.setPadding(left + bars.left, top + bars.top, right + bars.right, bottom + bars.bottom)
            insets
        }
        ViewCompat.requestApplyInsets(root)
    }

    fun parseExpiry(value: String?): Instant? = try {
        value?.takeIf { it.isNotBlank() }?.let(Instant::parse)
    } catch (_: Exception) { null }

    fun expiryLabel(context: Context, value: String?, forceExpired: Boolean = false): String {
        val expiry = parseExpiry(value) ?: return context.getString(R.string.request_tap_to_review)
        val locale = context.resources.configuration.locales[0]
        val formatter = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, locale)
        val expired = forceExpired || !expiry.isAfter(Instant.now())
        return context.getString(
            if (expired) R.string.request_expired_at else R.string.request_expires,
            formatter.format(Date.from(expiry)),
        )
    }

    fun connectionError(context: Context, error: Exception): String = when (error) {
        is ApiException -> when (error.statusCode) {
            401, 403 -> context.getString(R.string.connection_unauthorized)
            404 -> context.getString(R.string.connection_not_found)
            409 -> context.getString(R.string.connection_conflict)
            else -> context.getString(R.string.connection_http_error, error.statusCode)
        }
        is java.net.SocketTimeoutException -> context.getString(R.string.connection_timeout)
        is java.io.IOException -> context.getString(R.string.connection_unreachable)
        else -> error.localizedMessage ?: context.getString(R.string.error_generic)
    }
}

internal class HomeScreen(private val activity: AppCompatActivity) {
    val statusTitle: TextView = activity.findViewById(R.id.enrollStatusText)
    val enrollButton: Button = activity.findViewById(R.id.enrollButton)
    val refreshButton: ImageButton = activity.findViewById(R.id.refreshButton)
    private val container: LinearLayout = activity.findViewById(R.id.pendingApprovalsContainer)
    private val count: TextView = activity.findViewById(R.id.pendingCount)
    private val progress: View = activity.findViewById(R.id.loadingProgress)
    private var renderedContent: String? = null

    fun setLoading(loading: Boolean) {
        progress.visibility = if (loading) View.VISIBLE else View.GONE
    }

    fun setDeviceState(status: String, deviceId: String? = null, description: String? = null) {
        statusTitle.text = description?.takeIf { it.isNotBlank() } ?: when (status) {
            "approved", "checking" -> if (deviceId != null) {
                activity.getString(R.string.device_ready_description, deviceId.take(12))
            } else activity.getString(R.string.device_checking_title)
            "pending_manual_approval" -> if (deviceId != null) {
                activity.getString(R.string.device_pending_description, deviceId.take(12))
            } else activity.getString(R.string.device_pending_title)
            "enrolling" -> activity.getString(R.string.device_enrolling)
            "error" -> activity.getString(R.string.device_retry_title)
            "not_enrolled" -> activity.getString(R.string.not_enrolled)
            else -> activity.getString(R.string.device_unknown_title)
        }
        statusTitle.setTextColor(ContextCompat.getColor(activity,
            if (status == "error") R.color.cs_error else R.color.cs_text))
        enrollButton.setText(R.string.enroll)
        enrollButton.isEnabled = deviceId == null && status !in listOf("enrolling", "checking", "pending_manual_approval", "approved")
    }

    fun showEmpty(title: String, description: String = "", error: Boolean = false, countLabel: String? = null) {
        count.text = countLabel ?: formattedCount(0)
        val key = "$title|$description|$error|$countLabel"
        if (renderedContent == key) return
        renderedContent = key
        container.removeAllViews()
        val state = activity.layoutInflater.inflate(R.layout.view_empty_state, container, false)
        state.findViewById<TextView>(R.id.stateTitle).apply {
            text = title
            setTextColor(ContextCompat.getColor(activity, if (error) R.color.cs_error else R.color.cs_text_secondary))
        }
        state.findViewById<TextView>(R.id.stateDescription).apply {
            text = description
            visibility = if (description.isBlank()) View.GONE else View.VISIBLE
        }
        container.addView(state)
    }

    private fun formattedCount(value: Int): String =
        NumberFormat.getIntegerInstance(activity.resources.configuration.locales[0]).format(value)

    fun showRequests(approvals: JSONArray, onOpen: (String) -> Unit) {
        count.text = formattedCount(approvals.length())
        if (approvals.length() == 0) {
            showEmpty(activity.getString(R.string.no_pending_approvals))
            return
        }
        val key = approvals.toString()
        if (renderedContent == key) return
        renderedContent = key
        container.removeAllViews()
        for (index in 0 until approvals.length()) {
            val approval = approvals.getJSONObject(index)
            val ref = approval.getString("ref")
            val message = approval.getString("message")
            val row = activity.layoutInflater.inflate(R.layout.item_request, container, false)
            row.findViewById<TextView>(R.id.requestRef).text = activity.getString(R.string.request_reference, ref)
            row.findViewById<TextView>(R.id.requestMessage).text = message
            row.findViewById<TextView>(R.id.requestMeta).text = ScreenUi.expiryLabel(activity, approval.optString("expires_at"))
            row.setOnClickListener { onOpen(ref) }
            container.addView(row)
        }
    }
}
