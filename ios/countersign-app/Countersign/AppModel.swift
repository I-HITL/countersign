import Foundation
import LocalAuthentication
import Observation

@MainActor
@Observable
final class AppModel {
    var serverURL = UserDefaults.standard.string(forKey: "serverURL") ?? AppModel.defaultServerURL
    var accessToken = CredentialStore.token().isEmpty ? AppModel.defaultAccessToken : CredentialStore.token()
    private(set) var deviceID: String? = UserDefaults.standard.string(forKey: "deviceID")
    private(set) var enrollmentStatus = UserDefaults.standard.string(forKey: "enrollmentStatus") ?? "not_enrolled"
    var pending: [PendingApproval] = []
    private var activeOperations = 0
    var isWorking: Bool { activeOperations > 0 }
    var message: String?

    init() {
#if DEBUG
        // Explicit developer provisioning; normal launches use the saved connection.
        // Credentials go through Keychain and never appear in app logs or source.
        let environment = ProcessInfo.processInfo.environment
        if let url = environment["COUNTERSIGN_SETUP_URL"],
           let token = environment["COUNTERSIGN_SETUP_TOKEN"] {
            saveConnection(serverURL: url, accessToken: token)
        }
#endif
    }

    private static var defaultServerURL: String {
#if targetEnvironment(simulator)
        "http://127.0.0.1:8000"
#else
        "https://"
#endif
    }

    private static var defaultAccessToken: String {
#if targetEnvironment(simulator)
        "development-device-token"
#else
        ""
#endif
    }

    var client: APIClient? {
        guard let url = Self.validatedServerURL(serverURL), !accessToken.isEmpty else { return nil }
        return APIClient(baseURL: url, token: accessToken)
    }

    @discardableResult
    func saveConnection(serverURL proposedURL: String, accessToken proposedToken: String) -> Bool {
        guard !isWorking else { message = "Wait for the current operation to finish."; return false }
        guard let url = Self.validatedServerURL(proposedURL) else {
            message = "Enter a complete HTTPS server URL, or loopback HTTP for local development."
            return false
        }
        let token = proposedToken.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else { message = "Enter a device access token."; return false }
        do {
            // Preserve the previous connection when Keychain refuses a credential update.
            try CredentialStore.saveToken(token)
            if serverURL != url.absoluteString || accessToken != token { pending = [] }
            serverURL = url.absoluteString
            accessToken = token
            UserDefaults.standard.set(serverURL, forKey: "serverURL")
            message = nil
            // Keep the enrollment/key until the new service explicitly reports it missing.
            return true
        } catch {
            message = error.localizedDescription
            return false
        }
    }

    private static func validatedServerURL(_ value: String) -> URL? {
        guard let components = URLComponents(string: value.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = components.scheme?.lowercased(),
              let host = components.host, !host.isEmpty,
              host.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
              components.user == nil, components.password == nil,
              components.query == nil, components.fragment == nil else { return nil }
        let isLoopback = scheme == "http" && (host == "127.0.0.1" || host.lowercased() == "localhost")
        guard scheme == "https" || isLoopback else { return nil }
        return components.url
    }

    /// Attest the app, then bind its biometric confirmation key to that identity.
    /// Administrator approval is required before the device can receive requests.
    func enroll() async {
        guard !isWorking else { return }
        guard let client else { message = "Configure the backend connection first."; return }
        await perform {
            let begin = try await client.beginEnrollment()
            guard let challenge = Data(base64Encoded: begin.challengeBase64) else {
                throw APIError.server("The server returned an invalid attestation challenge.")
            }
            let attestedKey = try await AppAttestEnrollmentService.shared.createAttestedKey(challenge: challenge)
            let attestationResp = try await client.submitAttestation(
                enrollmentID: begin.enrollmentID, keyID: attestedKey.keyID, attestation: attestedKey.attestation
            )
            guard let bindingChallenge = Data(base64Encoded: attestationResp.bindingChallengeBase64) else {
                throw APIError.server("The server returned an invalid binding challenge.")
            }

            let confirmationPublicKeyDER = try await SigningService.shared.publicKeyDER()
            let payload = confirmationPublicKeyDER + bindingChallenge
            let confirmationSignature = try await SigningService.shared.signAfterExplicitApproval(payload)
            let assertion = try await AppAttestEnrollmentService.shared.assertion(keyID: attestedKey.keyID, clientData: payload)

            let result = try await client.submitBinding(
                enrollmentID: begin.enrollmentID,
                confirmationPublicKeyDER: confirmationPublicKeyDER,
                confirmationSignature: confirmationSignature,
                assertion: assertion
            )
            deviceID = result.deviceID
            enrollmentStatus = result.status
            UserDefaults.standard.set(result.deviceID, forKey: "deviceID")
            UserDefaults.standard.set(result.status, forKey: "enrollmentStatus")
            message = "Technical verification succeeded. Enrollment is pending administrator approval."
            await refresh()
        }
    }

    func refresh() async {
        guard let client, let deviceID else { return }
        activeOperations += 1
        defer { activeOperations -= 1 }
        do {
            let status = try await client.enrollmentStatus(deviceID: deviceID)
            enrollmentStatus = status.status
            UserDefaults.standard.set(status.status, forKey: "enrollmentStatus")
            pending = status.status == "approved" ? try await client.pendingApprovals(deviceID: deviceID) : []
        } catch let error as APIError where error.isNotFound {
            self.deviceID = nil
            enrollmentStatus = "not_enrolled"
            pending = []
            UserDefaults.standard.removeObject(forKey: "deviceID")
            UserDefaults.standard.removeObject(forKey: "enrollmentStatus")
            message = "The server no longer recognizes this installation. You can enroll this device again."
        } catch {
            message = friendly(error)
        }
    }

    @discardableResult
    func approve(_ approval: PendingApproval) async -> Bool {
        guard !isWorking else { return false }
        guard let client else { message = "Configure the backend connection first."; return false }
        guard !approval.isExpired else { message = "This request has expired."; return false }
        return await perform {
            // Signs exactly the UTF-8 bytes of the message shown on
            // screen -- nothing else. WYSIWYS, same as Android's
            // ApprovalActivity.kt. See docs/SECURITY.md.
            let signature = try await SigningService.shared.signAfterExplicitApproval(Data(approval.message.utf8))
            guard !approval.isExpired else {
                throw APIError.server("Expired during authentication. Nothing was submitted.")
            }
            let result = try await client.approve(ref: approval.ref, signature: signature)
            if result.status == "approved" || result.status == "rejected" {
                pending.removeAll { $0.ref == approval.ref }
            }
            await refresh()
            guard result.status == "approved" else {
                let detail = result.reasons.joined(separator: "\n")
                throw APIError.server(detail.isEmpty ? "Approval verification failed." : "Approval verification failed.\n\(detail)")
            }
        }
    }

    @discardableResult
    func decline(_ approval: PendingApproval) async -> Bool {
        guard !isWorking else { return false }
        guard let client else { message = "Configure the backend connection first."; return false }
        guard !approval.isExpired else { message = "This request has expired."; return false }
        return await perform {
            let result = try await client.decline(ref: approval.ref)
            guard result.status == "declined" else {
                throw APIError.server("Could not decline this request.")
            }
            pending.removeAll { $0.ref == approval.ref }
            await refresh()
        }
    }

    @discardableResult
    private func perform(_ operation: () async throws -> Void) async -> Bool {
        activeOperations += 1
        defer { activeOperations -= 1 }
        do {
            try await operation()
            return true
        } catch {
            message = friendly(error)
            return false
        }
    }

    private func friendly(_ error: Error) -> String {
        let nsError = error as NSError
        if nsError.domain == LAError.errorDomain, let code = LAError.Code(rawValue: nsError.code) {
            switch code {
            case .userCancel, .appCancel, .systemCancel: return "Face ID approval was cancelled. Nothing was signed."
            case .biometryLockout: return "Face ID is locked. Unlock it in system settings; passcode fallback is not used."
            case .biometryNotAvailable, .biometryNotEnrolled: return "Face ID is unavailable or not enrolled."
            default: return "Face ID authorization failed. The biometric set may have changed. Re-enrollment may be required."
            }
        }
        return error.localizedDescription
    }
}
