import CryptoKit
import Foundation
import LocalAuthentication

/// A biometric-gated Secure Enclave confirmation key, bound to the App Attest
/// identity during enrollment. This separate key signs each approval.
actor SigningService {
    static let shared = SigningService()
    private let identifier = "com.countersign.biometric-signing.v1"

    /// DER SubjectPublicKeyInfo, converted from the Secure Enclave key's X9.63 point.
    func publicKeyDER() async throws -> Data {
#if targetEnvironment(simulator)
        throw SigningError.hardwareUnavailable
#else
        let right = try await existingOrNewRight()
        let x963 = try await right.key.publicKey.bytes
        return try P256.Signing.PublicKey(x963Representation: x963).derRepresentation
#endif
    }

    func signAfterExplicitApproval(_ bytes: Data) async throws -> Data {
#if targetEnvironment(simulator)
        throw SigningError.hardwareUnavailable
#else
        let right = try await existingOrNewRight()
        do {
            try await right.checkCanAuthorize()
            try await right.authorize(localizedReason: "Approve this exact request")
            guard right.key.canSign(using: .ecdsaSignatureMessageX962SHA256) else {
                throw SigningError.unsupportedAlgorithm
            }
            let signature = try await right.key.sign(bytes, algorithm: .ecdsaSignatureMessageX962SHA256)
            await right.deauthorize()
            return signature
        } catch {
            await right.deauthorize()
            throw error
        }
#endif
    }

#if !targetEnvironment(simulator)
    private func existingOrNewRight() async throws -> LAPersistedRight {
        do {
            return try await LARightStore.shared.right(forIdentifier: identifier)
        } catch {
            let requirement = LAAuthenticationRequirement.biometryCurrentSet
            return try await LARightStore.shared.saveRight(LARight(requirement: requirement), identifier: identifier)
        }
    }
#endif

}

enum SigningError: LocalizedError {
    case unsupportedAlgorithm
    case hardwareUnavailable

    var errorDescription: String? {
        switch self {
        case .unsupportedAlgorithm:
            "The Secure Enclave key does not support ECDSA P-256 with SHA-256."
        case .hardwareUnavailable:
            "Secure Enclave signing requires a physical iPhone. Simulator approval is unavailable."
        }
    }
}
