import AppKit
import SwiftUI

/// A reconstruction of the system's passkey sign-in sheet: the method chooser, the QR code
/// screen and the security key screens.
///
/// Sizes and spacing were measured from screenshots of the sheet on macOS 26.
struct PromptView: View {
    @Bindable var model: PromptModel
    @FocusState private var pinFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Button(action: model.goBack) {
                Image(systemName: "chevron.left")
                    .font(.system(size: 15, weight: .semibold))
                    .frame(width: 24, height: 24)
                    .background(Circle().fill(.primary.opacity(0.06)))
                    .overlay(Circle().strokeBorder(.primary.opacity(0.15), lineWidth: 0.5))
                    .contentShape(Circle())
            }
            .buttonStyle(.plain)
            .padding(.leading, -10)
            // The system sheet has no chevron once the phone is connected.
            .opacity(model.stage == .phone ? 0 : 1)

            switch model.stage {
            case .choose:
                heading.padding(.top, 10)
                chooser.padding(.top, 30)
                Spacer(minLength: 0)
            case .qrCode:
                heading.padding(.top, 10)
                Spacer(minLength: 0)
                // The card reaches down beside the Cancel button, as in the system sheet.
                qrCode.frame(maxWidth: .infinity).padding(.bottom, -14)
            case .phone, .activate, .pin, .failed:
                Spacer(minLength: 0)
                artwork
                heading.padding(.top, 20)
                if model.stage == .pin {
                    SecureField(SystemResources.text("PIN"), text: $model.pin)
                        .textFieldStyle(.roundedBorder)
                        .controlSize(.large)
                        .focused($pinFocused)
                        .onSubmit(model.submitPIN)
                        .onAppear { pinFocused = true }
                        .padding(.top, 22)
                }
                Spacer(minLength: 0)
            }

            HStack {
                Button(SystemResources.text("Cancel"), action: model.onCancel)
                    .buttonStyle(CapsuleButtonStyle(prominent: false))
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if model.stage == .choose {
                    Button(SystemResources.text("Continue")) { model.onContinue(model.method) }
                        .buttonStyle(CapsuleButtonStyle(prominent: true))
                        .keyboardShortcut(.defaultAction)
                } else if model.stage == .pin {
                    Button(SystemResources.text("Continue"), action: model.submitPIN)
                        .buttonStyle(CapsuleButtonStyle(prominent: true))
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(.init(top: 10, leading: 20, bottom: 18, trailing: 20))
        .frame(width: 486, height: model.stage == .qrCode || model.stage == .phone ? 478 : 390)
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(.rect(cornerRadius: 26, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 26, style: .continuous)
            .strokeBorder(.primary.opacity(0.18), lineWidth: 1))
    }

    /// The bold title with the explanatory text under it.
    private var heading: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(model.title)
                .font(.system(size: 17, weight: .bold))
                .fixedSize(horizontal: false, vertical: true)
            if !model.message.isEmpty {
                Text(model.message)
                    .font(.system(size: 13))
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    /// The large blue glyph above the heading on the single-purpose screens.
    @ViewBuilder private var artwork: some View {
        if model.stage == .phone {
            Image(nsImage: SystemResources.passwordsIcon)
                .resizable()
                .frame(width: 52, height: 52)
        } else {
            Image(nsImage: SystemResources.keyIcon(pointSize: 50))
                .renderingMode(.template)
                .foregroundStyle(Color.accentColor)
                .padding(.leading, 4)
        }
    }

    /// The grouped list of sign-in methods with radio buttons.
    private var chooser: some View {
        VStack(spacing: 0) {
            methodRow(.qrCode, title: SystemResources.text("Scan QR Code (CABLE title)")) {
                Image(systemName: "qrcode.viewfinder").font(.system(size: 22))
            }
            methodRow(.securityKey, title: SystemResources.text("Use Security Key")) {
                Image(nsImage: SystemResources.keyIcon(pointSize: 22)).renderingMode(.template)
            }
        }
        .padding(.vertical, 10)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(.primary.opacity(0.05)))
    }

    /// One selectable row of the chooser.
    ///
    /// - Parameters:
    ///   - method: The method this row selects.
    ///   - title: The row's label.
    ///   - icon: The glyph between the radio button and the label.
    private func methodRow(_ method: SignInMethod, title: String,
                           @ViewBuilder icon: () -> some View) -> some View {
        let selected = model.method == method
        return HStack(spacing: 10) {
            ZStack {
                Circle().fill(selected ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.primary.opacity(0.12)))
                if selected { Circle().fill(.white).frame(width: 6, height: 6) }
            }
            .frame(width: 16, height: 16)
            icon()
                .foregroundStyle(.secondary)
                .frame(width: 30)
            Text(title).font(.system(size: 13))
            Spacer()
        }
        .padding(.horizontal, 13)
        .frame(height: 40)
        .contentShape(Rectangle())
        .onTapGesture { model.method = method }
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
    }

    /// The QR code on a white card with the passkey badge over its centre, as the system
    /// sheet draws it. The code's error correction makes up for the modules the badge hides.
    @ViewBuilder private var qrCode: some View {
        if let image = model.qrImage {
            let ink = Color(nsColor: SystemResources.qrCodeColor)
            Image(nsImage: image)
                .interpolation(.none)
                .resizable()
                .frame(width: 292, height: 292)
                .padding(4)
                .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(.white))
                .overlay {
                    Image(systemName: "person.badge.key.fill")
                        .font(.system(size: 38))
                        .foregroundStyle(.white)
                        .frame(width: 72, height: 72)
                        .background(RoundedRectangle(cornerRadius: 17, style: .continuous).fill(ink))
                        .padding(4)
                        .background(RoundedRectangle(cornerRadius: 21, style: .continuous).fill(.white))
                }
        }
    }
}

/// The filled capsule buttons of the system sheet.
private struct CapsuleButtonStyle: ButtonStyle {
    /// `true` for the accent-coloured default button, `false` for the grey secondary one.
    var prominent: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .medium))
            .foregroundStyle(prominent ? Color.white : Color.primary)
            .padding(.horizontal, 14)
            .frame(height: 28)
            .background(Capsule().fill(prominent ? AnyShapeStyle(Color.accentColor) : AnyShapeStyle(.primary.opacity(0.1))))
            .opacity(configuration.isPressed ? 0.7 : 1)
    }
}

/// A borderless panel, which cannot take keyboard focus unless it says it can.
private final class PromptPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
}

/// Shows the prompt as a floating, centred panel and brings the process to the front.
///
/// Must be called on the main thread after `NSApplication.shared` exists.
///
/// - Parameter model: The state the prompt displays and reports user actions to.
func showPromptPanel(_ model: PromptModel) {
    let panel = PromptPanel(contentRect: .zero, styleMask: [.borderless], backing: .buffered, defer: false)
    // The QR code screen is taller than the others; let the panel follow the view's size.
    let controller = NSHostingController(rootView: PromptView(model: model))
    controller.sizingOptions = .preferredContentSize
    panel.contentViewController = controller
    panel.isOpaque = false
    panel.backgroundColor = .clear
    panel.hasShadow = true
    panel.level = .floating
    panel.isMovableByWindowBackground = true
    panel.isReleasedWhenClosed = false
    // Panels hide themselves by default when their app is not frontmost, which happens as
    // soon as a system prompt (such as the Bluetooth permission) or another app takes focus.
    panel.hidesOnDeactivate = false
    panel.setContentSize(controller.view.fittingSize)
    panel.center()
    panel.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
}
