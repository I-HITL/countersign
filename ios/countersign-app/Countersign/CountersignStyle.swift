import SwiftUI

enum CountersignStyle {
    static let navy = Color(red: 23 / 255, green: 42 / 255, blue: 58 / 255)
    static let secondary = Color(red: 91 / 255, green: 103 / 255, blue: 112 / 255)
    static let green = Color(red: 40 / 255, green: 124 / 255, blue: 57 / 255)
    static let red = Color(red: 173 / 255, green: 52 / 255, blue: 52 / 255)
    static let outline = Color(red: 224 / 255, green: 229 / 255, blue: 226 / 255)
    static let disabled = Color(red: 220 / 255, green: 227 / 255, blue: 222 / 255)
    static let disabledText = Color(red: 104 / 255, green: 119 / 255, blue: 109 / 255)
}

struct CountersignButtonStyle: ButtonStyle {
    enum Kind { case primary, secondary, decline }
    let kind: Kind
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .multilineTextAlignment(.center)
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
            .frame(minHeight: 56)
            .foregroundStyle(foreground)
            .background(background, in: RoundedRectangle(cornerRadius: 12))
            .overlay {
                if kind != .primary {
                    RoundedRectangle(cornerRadius: 12).stroke(CountersignStyle.outline, lineWidth: 1)
                }
            }
            .opacity(configuration.isPressed ? 0.78 : 1)
    }

    private var foreground: Color {
        guard isEnabled else { return CountersignStyle.disabledText }
        switch kind {
        case .primary: return .white
        case .secondary: return CountersignStyle.navy
        case .decline: return CountersignStyle.red
        }
    }

    private var background: Color {
        kind == .primary ? (isEnabled ? CountersignStyle.green : CountersignStyle.disabled) : .white
    }
}

struct StatusMessage: View {
    let text: String
    var isError = false

    var body: some View {
        Text(text)
            .font(.subheadline)
            .foregroundStyle(isError ? CountersignStyle.red : CountersignStyle.green)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(isError ? Color(red: 252 / 255, green: 236 / 255, blue: 236 / 255)
                        : Color(red: 227 / 255, green: 243 / 255, blue: 230 / 255),
                        in: RoundedRectangle(cornerRadius: 12))
    }
}

extension View {
    @ViewBuilder func homeNavigation() -> some View {
#if os(iOS)
        self.toolbar(.hidden, for: .navigationBar)
#else
        self
#endif
    }

    @ViewBuilder func reviewNavigation() -> some View {
#if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
            .toolbar(.visible, for: .navigationBar)
            .toolbarBackground(.white, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
#else
        self
#endif
    }
}
