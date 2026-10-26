package com.example.countersign

/** Isolated, local-only simulation service; use adb reverse tcp:8001 tcp:8001. */
object AppConfig {
    const val BASE_URL = "http://127.0.0.1:8001"
    const val DEVICE_API_TOKEN = "development-device-token"
}
