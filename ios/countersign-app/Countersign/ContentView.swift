import SwiftUI

struct ContentView: View {
    @State private var model = AppModel()
    @State private var showingConnection = false

    var body: some View {
        NavigationStack {
            HomeScreen(
                status: enrollmentText,
                enrollmentEnabled: model.deviceID == nil,
                isWorking: model.isWorking,
                requests: model.pending,
                onEnroll: {
                    if model.client == nil { showingConnection = true }
                    else { Task { await model.enroll() } }
                },
                onRefresh: { Task { await model.refresh() } },
                onSettings: { showingConnection = true }
            )
            .refreshable { await model.refresh() }
            .navigationDestination(for: PendingApproval.self) { approval in
                RequestDetailView(approval: approval, model: model)
            }
            .homeNavigation()
        }
        .tint(CountersignStyle.green)
        .preferredColorScheme(.light)
        .task { await model.refresh() }
        .sheet(isPresented: $showingConnection) { ConnectionView(model: model) }
        .alert("Countersign", isPresented: Binding(
            get: { model.message != nil },
            set: { if !$0 { model.message = nil } }
        )) {
            Button("OK") { model.message = nil }
        } message: {
            Text(model.message ?? "")
        }
    }

    private var enrollmentText: String {
        switch model.enrollmentStatus {
        case "approved":
            "Enrolled: \(model.deviceID.map { String($0.prefix(12)) } ?? "")..."
        case "pending_manual_approval":
            "Pending administrator approval\n\(model.deviceID.map { String($0.prefix(12)) + "…" } ?? "")"
        case "not_enrolled": model.isWorking ? "Enrolling…" : "Not enrolled yet."
        case "rejected": "Enrollment declined"
        default: "Enrollment unavailable"
        }
    }
}

struct HomeScreen: View {
    let status: String
    let enrollmentEnabled: Bool
    let isWorking: Bool
    let requests: [PendingApproval]
    let onEnroll: () -> Void
    let onRefresh: () -> Void
    var onSettings: (() -> Void)? = nil
    var emptyText = "Nothing pending right now."

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 12) {
                    Image("CountersignSymbol")
                        .resizable().scaledToFit().frame(width: 48, height: 48)
                        .accessibilityHidden(true)
                    Text("Countersign")
                        .font(.title.weight(.medium))
                        .foregroundStyle(CountersignStyle.navy)
                        .minimumScaleFactor(0.8)
                }
                .frame(maxWidth: .infinity)
                .padding(.top, 24)
                .padding(.bottom, 40)
                .overlay(alignment: .topTrailing) {
                    if let onSettings {
                        Button(action: onSettings) {
                            Image(systemName: "gearshape")
                                .font(.body)
                                .frame(width: 44, height: 44)
                        }
                        .foregroundStyle(CountersignStyle.secondary)
                        .accessibilityLabel("Connection settings")
                        .offset(y: -18)
                    }
                }

                Text(status)
                    .font(.body)
                    .foregroundStyle(CountersignStyle.navy)
                    .accessibilityIdentifier("enrollmentStatus")

                if isWorking {
                    ProgressView().tint(CountersignStyle.green)
                        .frame(maxWidth: .infinity).padding(.top, 12)
                }

                Button("Enroll this device", action: onEnroll)
                    .buttonStyle(CountersignButtonStyle(kind: .primary))
                    .disabled(!enrollmentEnabled || isWorking)
                    .frame(maxWidth: .infinity)
                    .padding(.top, 16)

                HStack {
                    Text("Pending approvals")
                        .font(.headline)
                        .foregroundStyle(CountersignStyle.navy)
                        .accessibilityAddTraits(.isHeader)
                    Spacer()
                    Button(action: onRefresh) {
                        Image(systemName: "arrow.clockwise")
                            .font(.title3)
                            .frame(width: 44, height: 44)
                    }
                    .foregroundStyle(CountersignStyle.secondary)
                    .disabled(isWorking)
                    .accessibilityLabel("Refresh pending approvals")
                }
                .padding(.top, 28)
                .padding(.bottom, 8)

                if requests.isEmpty {
                    Text(emptyText)
                        .font(.body)
                        .foregroundStyle(CountersignStyle.secondary)
                        .padding(.vertical, 16)
                } else {
                    VStack(spacing: 12) {
                        ForEach(requests) { approval in
                            NavigationLink(value: approval) {
                                RequestRow(approval: approval)
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: 600)
            .frame(maxWidth: .infinity)
        }
        .background(Color.white)
    }
}

struct RequestRow: View {
    let approval: PendingApproval

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(approval.message)
                .font(.body)
                .foregroundStyle(CountersignStyle.navy)
                .lineLimit(4)
                .multilineTextAlignment(.leading)
            ExpiryLabel(expiry: approval.expiresAt)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(Color.white, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(CountersignStyle.outline, lineWidth: 1))
        .contentShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct RequestDetailView: View {
    let approval: PendingApproval
    let model: AppModel
    @State private var result: String?
    @Environment(\.isSceneCaptured) private var isSceneCaptured

    var body: some View {
        ReviewScreen(
            approval: approval,
            isWorking: model.isWorking,
            result: result,
            blockingReason: isSceneCaptured ? "Stop screen recording or mirroring before approving." : nil,
            onApprove: {
                guard !isSceneCaptured else { return }
                Task { if await model.approve(approval) { result = "Approved" } }
            },
            onDecline: {
                Task { if await model.decline(approval) { result = "Declined" } }
            }
        )
    }
}

struct ReviewScreen: View {
    let approval: PendingApproval
    var isWorking = false
    var result: String? = nil
    var blockingReason: String? = nil
    let onApprove: () -> Void
    let onDecline: () -> Void

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let expired = approval.expiresAt <= context.date
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    // The complete displayed string is also the exact UTF-8 message signed.
                    Text(approval.message)
                        .font(.title3)
                        .lineSpacing(5)
                        .foregroundStyle(CountersignStyle.navy)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .accessibilityIdentifier("approvalMessage")
                    ExpiryLabel(expiry: approval.expiresAt, now: context.date)
                        .padding(.top, 16)
                    if let blockingReason {
                        StatusMessage(text: blockingReason, isError: true).padding(.top, 16)
                    }
                    if let result {
                        StatusMessage(text: result).padding(.top, 16)
                            .accessibilityIdentifier("approvalResult")
                    }
                    if isWorking {
                        ProgressView().tint(CountersignStyle.green)
                            .frame(maxWidth: .infinity).padding(.top, 16)
                    }
                    Button(action: onApprove) {
                        HStack(spacing: 12) {
                            Text("Approve with Face ID")
                            Image(systemName: "faceid").font(.title2).accessibilityHidden(true)
                        }
                        .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(CountersignButtonStyle(kind: .primary))
                    .disabled(expired || isWorking || result != nil || blockingReason != nil)
                    .padding(.top, 32)
                    .accessibilityIdentifier("approveButton")

                    Button(action: onDecline) {
                        Text("Decline").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(CountersignButtonStyle(kind: .decline))
                    .disabled(expired || isWorking || result != nil)
                    .padding(.top, 12)
                    .accessibilityIdentifier("declineButton")
                }
                .padding(24)
                .padding(.top, 8)
                .frame(maxWidth: 600)
                .frame(maxWidth: .infinity)
            }
            .background(Color.white)
        }
        .navigationTitle("Review request")
        .reviewNavigation()
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Image("CountersignSymbol")
                    .resizable().scaledToFit().frame(width: 36, height: 36)
                    .accessibilityHidden(true)
            }
        }
    }
}

struct ExpiryLabel: View {
    let expiry: Date
    var now: Date? = nil

    var body: some View {
        if let now {
            label(at: now)
        } else {
            TimelineView(.periodic(from: .now, by: 1)) { context in label(at: context.date) }
        }
    }

    private func label(at date: Date) -> some View {
        let expired = expiry <= date
        return Text("\(expired ? "Expired" : "Expires") \(expiry.formatted(date: .abbreviated, time: .shortened))")
            .font(.subheadline)
            .foregroundStyle(expired ? CountersignStyle.red : CountersignStyle.secondary)
            .accessibilityIdentifier("approvalExpiry")
    }
}

struct ConnectionView: View {
    let model: AppModel
    @State private var serverURL: String
    @State private var accessToken: String
    @State private var saveError: String?
    @Environment(\.dismiss) private var dismiss

    init(model: AppModel) {
        self.model = model
        _serverURL = State(initialValue: model.serverURL)
        _accessToken = State(initialValue: model.accessToken)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("https://your-server.example.com", text: $serverURL)
                        .autocorrectionDisabled()
#if os(iOS)
                        .textInputAutocapitalization(.never)
                        .keyboardType(.URL)
#endif
                    SecureField("Device access token", text: $accessToken)
                        .autocorrectionDisabled()
#if os(iOS)
                        .textInputAutocapitalization(.never)
#endif
                    Button("Save connection") {
                        if model.saveConnection(serverURL: serverURL, accessToken: accessToken) {
                            dismiss()
                            Task { await model.refresh() }
                        } else {
                            saveError = model.message
                            model.message = nil
                        }
                    }
                    .foregroundStyle(CountersignStyle.green)
                    .disabled(model.isWorking)
                    if let saveError {
                        Text(saveError).foregroundStyle(CountersignStyle.red).font(.footnote)
                    }
                }
                if let deviceID = model.deviceID {
                    Section("Device") {
                        LabeledContent("Device ID") { Text(deviceID).textSelection(.enabled) }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Color.white)
            .navigationTitle("Connection")
            .reviewNavigation()
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
        }
        .tint(CountersignStyle.green)
        .preferredColorScheme(.light)
    }
}
