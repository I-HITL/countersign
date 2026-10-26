package com.example.countersign

import android.content.Context
import java.security.cert.Certificate

/**
 * Emulator-only trust evidence. The service must explicitly enable simulation.
 * There is no hardware attestation or Play Integrity verdict in this variant.
 * AndroidKeyStore and BiometricPrompt still gate every actual approval signature.
 */
object DeviceTrust {
    @Suppress("UNUSED_PARAMETER")
    fun generateApprovalKey(challenge: ByteArray): List<Certificate> =
        // With no attestation challenge, this certificate only carries the
        // public key. It is not a trusted hardware-attestation certificate.
        KeystoreHelper.generateApprovalKey(KeystoreHelper.keySpecBuilder().build())

    @Suppress("UNUSED_PARAMETER")
    suspend fun requestIntegrityToken(context: Context, message: String): String =
        "android-simulation-only-not-a-play-integrity-token"
}
