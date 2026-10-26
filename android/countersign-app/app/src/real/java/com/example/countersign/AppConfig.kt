package com.example.countersign

/** Genuine-build settings supplied through the ignored deployment.properties. */
object AppConfig {
    const val BASE_URL = BuildConfig.BACKEND_URL
    // Device credentials are packaged in the app; administrator credentials must
    // remain on the backend. See docs/SECURITY.md for the demo's auth limitations.
    const val DEVICE_API_TOKEN = BuildConfig.DEVICE_API_TOKEN
    const val CLOUD_PROJECT_NUMBER = BuildConfig.CLOUD_PROJECT_NUMBER
}
