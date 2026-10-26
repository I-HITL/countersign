import Foundation

/// Mirrors service/models.py's PendingApprovalView exactly -- the server
/// renders one display string and that same string is what gets signed
/// (WYSIWYS). There is no structured payload to decode and re-render here;
/// an earlier version of this app did that, and service/crypto.py's
/// render_approval_message docstring explains why that approach was
/// rejected for the shared protocol.
struct PendingApproval: Codable, Identifiable, Equatable, Hashable, Sendable {
    let ref: String
    let message: String
    let status: String
    let expiresAt: Date

    enum CodingKeys: String, CodingKey {
        case ref, message, status
        case expiresAt = "expires_at"
    }

    var id: String { ref }
    var isExpired: Bool { expiresAt <= Date() }
}

struct BeginEnrollmentRequest: Codable, Sendable {
    let platform: String
}

struct BeginEnrollmentResponse: Codable, Sendable {
    let enrollmentID: String
    let challengeBase64: String
    let platform: String

    enum CodingKeys: String, CodingKey {
        case platform
        case enrollmentID = "enrollment_id"
        case challengeBase64 = "challenge_b64"
    }
}

struct SubmitIosAttestationRequest: Codable, Sendable {
    let keyID: String
    let attestationBase64: String

    enum CodingKeys: String, CodingKey {
        case keyID = "key_id"
        case attestationBase64 = "attestation_b64"
    }
}

struct SubmitIosAttestationResponse: Codable, Sendable {
    let bindingChallengeBase64: String
    let status: String

    enum CodingKeys: String, CodingKey {
        case status
        case bindingChallengeBase64 = "binding_challenge_b64"
    }
}

/// The payload both the confirmation signature and the App Attest
/// assertion cover is confirmationPublicKeyDER || bindingChallenge, raw
/// concatenated bytes -- not JSON. The server derives it itself from
/// pieces it already has rather than trusting a client-supplied blob, so
/// there's no separate payload field to send here.
struct SubmitIosBindingRequest: Codable, Sendable {
    let confirmationPublicKeyDERBase64: String
    let confirmationSignatureBase64: String
    let assertionBase64: String

    enum CodingKeys: String, CodingKey {
        case confirmationPublicKeyDERBase64 = "confirmation_public_key_der_b64"
        case confirmationSignatureBase64 = "confirmation_signature_b64"
        case assertionBase64 = "assertion_b64"
    }
}

struct CompleteEnrollmentResponse: Codable, Sendable {
    let deviceID: String
    let status: String
    enum CodingKeys: String, CodingKey { case status; case deviceID = "device_id" }
}

struct EnrollmentStatusResponse: Codable, Sendable {
    let deviceID: String
    let status: String
    enum CodingKeys: String, CodingKey { case status; case deviceID = "device_id" }
}

/// No integrity_token field -- iOS devices must not send one at all (the
/// server rejects it if present). See docs/SECURITY.md for
/// why there's no per-approval analog of Android's Play Integrity token.
struct CompleteApprovalRequest: Codable, Sendable {
    let signatureBase64: String
    enum CodingKeys: String, CodingKey { case signatureBase64 = "signature_b64" }
}

struct CompleteApprovalResponse: Codable, Sendable {
    let ref: String
    let status: String
    let reasons: [String]
}
