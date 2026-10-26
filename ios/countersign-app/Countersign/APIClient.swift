import Foundation
import Security

/// Client for the shared Countersign service (see service/app.py at the
/// repo root -- this app no longer talks to a separate iOS-only backend).
/// Every request uses the device-scoped bearer credential. Administrator
/// credentials are deliberately never accepted or stored by this client.
struct APIClient: Sendable {
    let baseURL: URL
    let token: String

    func beginEnrollment() async throws -> BeginEnrollmentResponse {
        try await send(path: "/v1/enroll/begin", method: "POST", body: BeginEnrollmentRequest(platform: "ios"))
    }

    func submitAttestation(enrollmentID: String, keyID: String, attestation: Data) async throws -> SubmitIosAttestationResponse {
        try await send(
            path: "/v1/enroll/\(enrollmentID)/attestation", method: "POST",
            body: SubmitIosAttestationRequest(keyID: keyID, attestationBase64: attestation.base64EncodedString())
        )
    }

    func submitBinding(
        enrollmentID: String, confirmationPublicKeyDER: Data, confirmationSignature: Data, assertion: Data
    ) async throws -> CompleteEnrollmentResponse {
        try await send(
            path: "/v1/enroll/\(enrollmentID)/binding", method: "POST",
            body: SubmitIosBindingRequest(
                confirmationPublicKeyDERBase64: confirmationPublicKeyDER.base64EncodedString(),
                confirmationSignatureBase64: confirmationSignature.base64EncodedString(),
                assertionBase64: assertion.base64EncodedString()
            )
        )
    }

    func pendingApprovals(deviceID: String) async throws -> [PendingApproval] {
        try await send(path: "/v1/approvals?device_id=\(deviceID)")
    }

    func enrollmentStatus(deviceID: String) async throws -> EnrollmentStatusResponse {
        try await send(path: "/v1/enrollments/\(deviceID)")
    }

    func approve(ref: String, signature: Data) async throws -> CompleteApprovalResponse {
        try await send(
            path: "/v1/approvals/\(ref)/complete", method: "POST",
            body: CompleteApprovalRequest(signatureBase64: signature.base64EncodedString())
        )
    }

    func decline(ref: String) async throws -> CompleteApprovalResponse {
        try await send(path: "/v1/approvals/\(ref)/decline", method: "POST", body: Optional<String>.none)
    }

    private func send<Response: Decodable, Body: Encodable>(
        path: String, method: String = "GET", body: Body? = Optional<String>.none
    ) async throws -> Response {
        guard let url = URL(string: path, relativeTo: baseURL) else { throw APIError.invalidURL }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let body { request.httpBody = try JSONEncoder().encode(body) }
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw APIError.invalidResponse }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder().decode(ErrorResponse.self, from: data).message) ?? "HTTP \(http.statusCode)"
            throw APIError.http(statusCode: http.statusCode, message: detail)
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let string = try container.decode(String.self)
            // FastAPI/pydantic emit fractional-second ISO-8601
            // ("...346178Z"); the default formatter rejects that, so try
            // with fractional seconds first and fall back without them.
            let withFractional = ISO8601DateFormatter()
            withFractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let date = withFractional.date(from: string) { return date }
            let plain = ISO8601DateFormatter()
            plain.formatOptions = [.withInternetDateTime]
            if let date = plain.date(from: string) { return date }
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid date: \(string)")
        }
        return try decoder.decode(Response.self, from: data)
    }
}

struct CredentialStore {
    private static let service = "CountersignBackend"

    static func saveToken(_ token: String) throws {
#if targetEnvironment(simulator)
        UserDefaults.standard.set(token, forKey: service)
#else
        let query = [kSecClass: kSecClassGenericPassword, kSecAttrService: service] as CFDictionary
        let updateStatus = SecItemUpdate(query, [kSecValueData: Data(token.utf8)] as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw APIError.server("Could not save the device credential.")
        }
        let status = SecItemAdd([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecValueData: Data(token.utf8),
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ] as CFDictionary, nil)
        guard status == errSecSuccess else { throw APIError.server("Could not save the device credential.") }
#endif
    }

    static func token() -> String {
#if targetEnvironment(simulator)
        return UserDefaults.standard.string(forKey: service) ?? ""
#else
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ] as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return "" }
        return String(decoding: data, as: UTF8.self)
#endif
    }
}

private struct ErrorResponse: Decodable {
    let message: String?

    private enum CodingKeys: String, CodingKey { case detail }
    private struct Reasons: Decodable { let reasons: [String] }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let text = try? container.decode(String.self, forKey: .detail), !text.isEmpty {
            message = text
        } else if let detail = try? container.decode(Reasons.self, forKey: .detail) {
            let reasons = detail.reasons.filter { !$0.isEmpty }
            message = reasons.isEmpty ? nil : reasons.joined(separator: "\n")
        } else {
            message = nil
        }
    }
}

enum APIError: LocalizedError {
    case invalidURL, invalidResponse, server(String)
    case http(statusCode: Int, message: String)

    var errorDescription: String? {
        switch self {
        case .invalidURL: "Invalid server URL."
        case .invalidResponse: "The server response was not HTTP."
        case .server(let message), .http(_, let message): message
        }
    }

    var isNotFound: Bool {
        if case .http(statusCode: 404, _) = self { return true }
        return false
    }
}
