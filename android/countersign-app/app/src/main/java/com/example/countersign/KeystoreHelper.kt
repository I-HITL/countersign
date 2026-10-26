package com.example.countersign

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.Certificate

/**
 * Shared AndroidKeyStore signing. Every variant requires a fresh
 * AUTH_BIOMETRIC_STRONG presentation for each signature. DeviceTrust
 * selects hardware attestation in real builds; the emulator simulation
 * makes no claim about hardware-backed key storage.
 */
object KeystoreHelper {
    private const val PROVIDER = "AndroidKeyStore"
    private const val ALIAS = "countersign_approval_key"

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(PROVIDER).apply { load(null) }

    /** Shared, per-operation biometric policy; build-specific trust adds attestation. */
    internal fun keySpecBuilder(): KeyGenParameterSpec.Builder =
        KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                /* timeout = */ 0, // 0 = required on every single use, not time-windowed
                KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
            .setInvalidatedByBiometricEnrollment(true)

    /** Replaces the enrollment key and returns the leaf-first public certificate chain. */
    internal fun generateApprovalKey(spec: KeyGenParameterSpec): List<Certificate> {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        generator.initialize(spec)
        generator.generateKeyPair()
        return keyStore().getCertificateChain(ALIAS).toList()
    }

    /**
     * A Signature primed with the approval key, ready to hand to
     * BiometricPrompt as a CryptoObject. The actual sign() call only
     * succeeds after the biometric prompt reports success -- that's what
     * enforces per-operation authentication through AndroidKeyStore. A real
     * device's hardware backing is independently checked by the service;
     * the simulation only exercises the emulator's biometric mechanism.
     */
    fun signatureForApproval(): Signature {
        val privateKey = keyStore().getKey(ALIAS, null) as java.security.PrivateKey
        return Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
    }
}
