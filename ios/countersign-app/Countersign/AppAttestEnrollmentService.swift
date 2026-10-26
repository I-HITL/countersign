import CryptoKit
import DeviceCheck
import Foundation

actor AppAttestEnrollmentService {
    static let shared = AppAttestEnrollmentService()

    struct AttestedKey: Sendable {
        let keyID: String
        let attestation: Data
    }

    func createAttestedKey(challenge: Data) async throws -> AttestedKey {
        let service = DCAppAttestService.shared
        guard service.isSupported else { throw AppAttestEnrollmentError.unsupported }
        let keyID = try await service.generateKey()
        let hash = Data(SHA256.hash(data: challenge))
        let attestation = try await service.attestKey(keyID, clientDataHash: hash)
        return AttestedKey(keyID: keyID, attestation: attestation)
    }

    func assertion(keyID: String, clientData: Data) async throws -> Data {
        let hash = Data(SHA256.hash(data: clientData))
        return try await DCAppAttestService.shared.generateAssertion(keyID, clientDataHash: hash)
    }
}

enum AppAttestEnrollmentError: LocalizedError {
    case unsupported
    var errorDescription: String? {
        "App Attest is unavailable. Use a signed physical iPhone build; Simulator enrollment cannot be activated."
    }
}
