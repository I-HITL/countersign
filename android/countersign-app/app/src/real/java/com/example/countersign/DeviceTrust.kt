package com.example.countersign

import android.content.Context
import android.security.keystore.StrongBoxUnavailableException
import java.security.cert.Certificate

/** Genuine Android Key Attestation and Play Integrity, in debug and release. */
object DeviceTrust {
    fun generateApprovalKey(challenge: ByteArray): List<Certificate> {
        fun keySpec(strongBox: Boolean) = KeystoreHelper.keySpecBuilder()
            .setAttestationChallenge(challenge)
            .setIsStrongBoxBacked(strongBox)
            .build()

        return try {
            KeystoreHelper.generateApprovalKey(keySpec(strongBox = true))
        } catch (error: StrongBoxUnavailableException) {
            KeystoreHelper.generateApprovalKey(keySpec(strongBox = false))
        }
    }

    suspend fun requestIntegrityToken(context: Context, message: String): String {
        check(AppConfig.CLOUD_PROJECT_NUMBER > 0) {
            "Configure cloudProjectNumber in deployment.properties and rebuild the app."
        }
        val provider = IntegrityHelper.warmUp(context, AppConfig.CLOUD_PROJECT_NUMBER)
        return IntegrityHelper.requestToken(provider, IntegrityHelper.computeRequestHash(message))
    }
}
