package com.example.countersign

import android.content.Context

/** Persists the server enrollment ID. A server 404 clears it so enrollment can restart. */
object DeviceState {
    private const val PREFS_NAME = "countersign_device_state"
    private const val KEY_DEVICE_ID = "device_id"

    fun saveDeviceId(context: Context, deviceId: String) {
        prefs(context).edit().putString(KEY_DEVICE_ID, deviceId).apply()
    }

    fun getDeviceId(context: Context): String? = prefs(context).getString(KEY_DEVICE_ID, null)

    fun clearDeviceId(context: Context) {
        prefs(context).edit().remove(KEY_DEVICE_ID).apply()
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
}
