import CFido2
import CGtk
import Foundation

// The Linux prompt: GTK 3 dialogs in the style of Chromium's own security key prompt, with
// Chromium's artwork. GTK is used through its C interface (the module CGtk), as libfido2 is
// through CFido2.
//
// GTK objects are C structures, some of which Swift sees as typed pointers and some as
// opaque ones, and C code converts between them with cast macros that Swift cannot call.
// Here every object is kept as an untyped pointer; `raw` turns what GTK returns into one,
// and `cast` turns it into whatever type the called function expects.

private typealias Object = UnsafeMutableRawPointer

private func raw<T>(_ pointer: UnsafeMutablePointer<T>?) -> Object? { UnsafeMutableRawPointer(pointer) }
private func raw(_ pointer: OpaquePointer?) -> Object? { UnsafeMutableRawPointer(pointer) }
private func cast<T>(_ object: Object?) -> UnsafeMutablePointer<T>! { object?.assumingMemoryBound(to: T.self) }
private func cast(_ object: Object?) -> OpaquePointer! { object.map { OpaquePointer($0) } }

/// A closure on its way to the GTK main loop.
private final class MainBlock {
    let body: () -> Void
    init(_ body: @escaping () -> Void) { self.body = body }
}

/// Runs a closure on the thread of the GTK main loop. May be called from any thread.
private func onMainLoop(_ body: @escaping () -> Void) {
    let block = Unmanaged.passRetained(MainBlock(body)).toOpaque()
    g_idle_add({ data in
        Unmanaged<MainBlock>.fromOpaque(data!).takeRetainedValue().body()
        return 0  // G_SOURCE_REMOVE: run once.
    }, block)
}

/// Shows the Linux prompt and runs the GTK main loop.
///
/// Never returns: the process exits when the request is done, fails or is cancelled.
///
/// - Parameters:
///   - request: What to sign, list or print.
///   - transport: The transport set on the command line. Only USB exists here, and the
///     command line has already refused `hybrid`.
func runPrompt(_ request: Request, transport: TransportOption) -> Never {
    // Printing the key's details asks nothing of the user, so it works without a display.
    guard request.rpId != nil || request.discover else {
        do {
            try FidoSession().run(request, ui: NoPrompt())
            exit(0)
        } catch {
            logger.error("\(error)")
            exit(1)
        }
    }
    guard GtkPrompt.initialize() else {
        logger.error("Cannot open the display; the prompt needs a graphical session (X11 or Wayland)")
        exit(1)
    }
    let runner = PromptRunner(request: request)
    runner.start()
    withExtendedLifetime(runner) { gtk_main() }
    exit(0)
}

/// The user interface of a request that needs none.
private final class NoPrompt: SessionUI {
    func showActivate(afterPIN: Bool) {}
    func requestPIN(incorrect: Bool, retries: Int?) -> String? { nil }
}

/// Runs security key sessions on a worker thread, one after another in flood mode, and ends
/// the process when one is done. Main-thread only, except where noted.
private final class PromptRunner {
    private let request: Request
    private let prompt = GtkPrompt()
    private let lock = NSLock()
    private var session: FidoSession?
    /// What the sessions of this request have done so far; see ``SessionProgress``.
    private let progress = SessionProgress()
    private var interrupt: DispatchSourceSignal?

    init(request: Request) {
        self.request = request
    }

    func start() {
        // Ctrl-C: stop the key waiting for a touch before going, so that it does not go on
        // blinking. GTK's main loop does not serve the dispatch main queue, hence a
        // background queue.
        signal(SIGINT, SIG_IGN)
        let interrupt = DispatchSource.makeSignalSource(signal: SIGINT, queue: .global())
        interrupt.setEventHandler { [self] in
            lock.lock()
            session?.cancel()
            lock.unlock()
            exit(130)
        }
        interrupt.resume()
        self.interrupt = interrupt
        prompt.onCancel = { [unowned self] in
            lock.lock()
            session?.cancel()
            lock.unlock()
        }
        startSession()
    }

    private func startSession() {
        let session = FidoSession(progress: progress)
        lock.lock()
        self.session = session
        lock.unlock()
        // No dialog yet: the session asks for one when the user has something to do.
        let request = request
        let prompt = prompt
        Thread.detachNewThread {
            do {
                try session.run(request, ui: prompt)
                exit(0)
            } catch {
                onMainLoop { self.ended(session, with: error) }
            }
        }
    }

    private func ended(_ session: FidoSession, with error: Error) {
        prompt.close()
        let cancelled = session.isCancelled || (error as? FidoError)?.code == FIDO_ERR_KEEPALIVE_CANCEL
        guard cancelled else {
            logger.error("\(error)")
            exit(1)
        }
        guard request.flood else {
            logger.info("Cancelled.")
            exit(1)
        }
        logger.info("Cancelled; flood mode starts again")
        startSession()
    }
}

/// The two dialogs of the Linux prompt: "touch your security key" and "enter the PIN".
///
/// One dialog is on screen at a time. The ``SessionUI`` methods are called on the session's
/// worker thread and hand over to the GTK main loop; everything else is main-loop only.
private final class GtkPrompt: SessionUI {
    /// The longest PIN CTAP allows, in bytes of UTF-8.
    private static let maximumPINBytes = 63
    /// The shortest PIN CTAP allows, in characters.
    private static let minimumPINCharacters = 4
    /// GTK's priority for an application's own style sheet (GTK_STYLE_PROVIDER_PRIORITY_APPLICATION).
    private static let applicationStylePriority: guint = 600

    private static var dark = false

    /// Called when the user cancels the touch dialog.
    var onCancel: () -> Void = {}

    private var dialog: Object?
    private var entry: Object?
    private var cancellingLabel: Object?
    private var waitingForPIN = false
    private var pinResult: String?
    private let pinAnswered = DispatchSemaphore(value: 0)

    // MARK: Setting up GTK

    /// Opens the display and prepares what all dialogs share: the style sheet and the
    /// window icon.
    ///
    /// - Returns: `false` if there is no graphical session.
    static func initialize() -> Bool {
        // Desktop shells pick the taskbar icon by the program name (Wayland) or the window
        // class (X11); "chromium" makes them show Chromium's icon and group the prompt with
        // the browser that is being troubleshot. The embedded logo covers shells that use
        // window icons instead.
        g_set_prgname("chromium")
        gdk_set_program_class("chromium")
        // X11 first, also in a Wayland session (through XWayland): native Wayland does not
        // let a program place its own windows. Failing that, whatever display there is.
        gdk_set_allowed_backends("x11,*")
        guard gtk_init_check(nil, nil) != 0 else { return false }
        if let name = gdk_display_get_name(gdk_display_get_default()), String(cString: name).hasPrefix("wayland") {
            logger.info("Native Wayland decides where windows go; the prompt is not centred near the top of the screen as it is under X11")
        }

        dark = phido2_prefers_dark_theme() != 0
        let provider = gtk_css_provider_new()
        if gtk_css_provider_load_from_data(provider, styleSheet(dark: dark), -1, nil) != 0 {
            gtk_style_context_add_provider_for_screen(gdk_screen_get_default(), cast(raw(provider)), applicationStylePriority)
        } else {
            logger.warning("The prompt's style sheet was not accepted; it is shown in the desktop's default style")
        }

        var icons: UnsafeMutablePointer<GList>?
        for picture in [PackageResources.product_logo_64_png, PackageResources.product_logo_128_png] {
            if let pixbuf = pixbuf(fromPNG: picture) { icons = g_list_append(icons, pixbuf) }
        }
        gtk_window_set_default_icon_list(icons)
        g_list_free_full(icons, g_object_unref)
        return true
    }

    /// Chromium's colours and shapes for the prompt, as a GTK style sheet.
    private static func styleSheet(dark: Bool) -> String {
        let text = dark ? "#e8eaed" : "#202124"
        let panel = dark ? "#2b2b2b" : "#ffffff"
        let accent = dark ? "#8ab4f8" : "#1a73e8"
        let muted = dark ? "#bdc1c6" : "#5f6368"
        let error = dark ? "#f28b82" : "#b3261e"
        let button = dark ? "#004a77" : "#d3e3fd"
        let buttonText = dark ? "#c2e7ff" : "#041e49"
        let disabled = dark ? "#3c4043" : "#e8eaed"
        let field = dark ? "#242424" : "#f1f3f4"
        let fieldLine = dark ? "#a8c7fa" : "#1a73e8"
        return """
            .fm-fido { background: transparent; color: \(text); font-family: 'Roboto', 'Arial', sans-serif; }
            .fm-fido .fm-panel { background: \(panel); border-radius: 12px; padding: 24px; }
            .fm-fido .fm-title { font-size: 18px; font-weight: 600; }
            .fm-fido .fm-detail { font-size: 16px; color: \(text); }
            .fm-fido .fm-pin-label { font-size: 14px; color: \(accent); }
            .fm-fido .fm-retry { font-size: 13px; color: \(muted); }
            .fm-fido .fm-error { color: \(error); font-size: 13px; }
            .fm-fido button { border-radius: 20px; padding: 7px 20px; background: \(button); color: \(buttonText); border: none; box-shadow: none; }
            .fm-fido button.suggested-action { background: #4285f4; color: #ffffff; border: none; }
            .fm-fido button.suggested-action:disabled { background: \(disabled); color: #9aa0a6; }
            .fm-fido entry { background: \(field); border: none; border-bottom: 2px solid \(fieldLine); border-radius: 4px 4px 0 0; box-shadow: none; padding: 6px 8px; }
            .fm-fido entry:focus { border-bottom-color: \(fieldLine); box-shadow: none; }
            """
    }

    /// Decodes a PNG file held in memory.
    ///
    /// The pictures are those in `Linux/chromium`, which SwiftPM compiles into the
    /// executable as `PackageResources` (see Package.swift).
    ///
    /// - Returns: A GdkPixbuf the caller owns, or `nil` if the bytes are not a picture.
    private static func pixbuf(fromPNG bytes: [UInt8]) -> Object? {
        let loader = gdk_pixbuf_loader_new()
        defer { g_object_unref(raw(loader)) }
        guard gdk_pixbuf_loader_write(loader, bytes, gsize(bytes.count), nil) != 0,
              gdk_pixbuf_loader_close(loader, nil) != 0,
              let pixbuf = raw(gdk_pixbuf_loader_get_pixbuf(loader)) else { return nil }
        // The loader owns the picture; keep it alive past the loader.
        _ = g_object_ref(pixbuf)
        return pixbuf
    }

    // MARK: SessionUI (worker thread)

    func showActivate(afterPIN: Bool) {
        onMainLoop { self.showTouchDialog(afterPIN: afterPIN) }
    }

    func requestPIN(incorrect: Bool, retries: Int?) -> String? {
        onMainLoop { self.showPINDialog(incorrect: incorrect, retries: retries) }
        pinAnswered.wait()
        // Written on the main loop before the semaphore was signalled.
        return pinResult
    }

    // MARK: Dialogs (main loop)

    /// Shows the dialog that tells the user to touch the security key.
    ///
    /// - Parameter afterPIN: `true` when the user has just entered a PIN.
    func showTouchDialog(afterPIN: Bool) {
        close()
        let body = makeDialog(title: "Use your security key",
                              detail: afterPIN ? "Touch your security key again to complete the request."
                                               : "Insert your security key and touch it to complete the request.")
        gtk_widget_set_margin_bottom(cast(body), 32)
        let label = addLabel(to: body, "Cancelling; waiting for the security key...", style: "fm-retry")
        // Hidden until Cancel is pressed; gtk_widget_show_all must leave it alone.
        gtk_widget_set_no_show_all(cast(label), 1)
        cancellingLabel = label
        present()
    }

    /// Shows the dialog that asks for the security key's PIN.
    ///
    /// - Parameters:
    ///   - incorrect: `true` when the previous PIN was rejected.
    ///   - retries: How many attempts the key still allows, if known.
    private func showPINDialog(incorrect: Bool, retries: Int?) {
        close()
        let body = makeDialog(title: "PIN required",
                              detail: incorrect ? "The PIN was incorrect. Enter the PIN for your security key"
                                                : "Enter the PIN for your security key")
        let box = raw(gtk_box_new(GTK_ORIENTATION_VERTICAL, 4))
        gtk_box_pack_start(cast(body), cast(box), 0, 0, 0)
        let caption = addLabel(to: box, "PIN", style: "fm-pin-label")

        let entry = raw(gtk_entry_new())
        gtk_entry_set_visibility(cast(entry), 0)
        gtk_entry_set_input_purpose(cast(entry), GTK_INPUT_PURPOSE_PASSWORD)
        gtk_entry_set_activates_default(cast(entry), 1)
        gtk_entry_set_max_length(cast(entry), gint(Self.maximumPINBytes))
        gtk_entry_set_width_chars(cast(entry), 14)
        gtk_widget_set_size_request(cast(entry), 180, 40)
        gtk_widget_set_halign(cast(entry), GTK_ALIGN_START)
        gtk_label_set_mnemonic_widget(cast(caption), cast(entry))
        atk_object_set_name(gtk_widget_get_accessible(cast(entry)), "PIN")
        gtk_box_pack_start(cast(box), cast(entry), 0, 0, 0)
        if let retries {
            _ = addLabel(to: box, "\(retries) PIN attempts remaining", style: "fm-error")
        }

        let next = raw(gtk_dialog_add_button(cast(dialog), "Next", GTK_RESPONSE_OK.rawValue))
        gtk_style_context_add_class(gtk_widget_get_style_context(cast(next)), "suggested-action")
        gtk_dialog_set_default_response(cast(dialog), GTK_RESPONSE_OK.rawValue)
        // Next stays disabled until the PIN has a valid length.
        gtk_dialog_set_response_sensitive(cast(dialog), GTK_RESPONSE_OK.rawValue, 0)
        let changed: @convention(c) (Object?, Object?) -> Void = { _, context in
            Unmanaged<GtkPrompt>.fromOpaque(context!).takeUnretainedValue().pinChanged()
        }
        _ = phido2_signal_connect(entry, "changed", unsafeBitCast(changed, to: GCallback.self), context)

        self.entry = entry
        waitingForPIN = true
        present()
        gtk_widget_grab_focus(cast(entry))
    }

    /// Removes the dialog from the screen, if one is showing.
    func close() {
        guard let dialog else { return }
        gtk_widget_destroy(cast(dialog))
        self.dialog = nil
        entry = nil
        cancellingLabel = nil
    }

    /// Builds what both dialogs have in common: the rounded panel, the illustration, the
    /// heading, the text and the Cancel button.
    ///
    /// - Returns: The box to add further rows to. The dialog itself is kept in ``dialog``.
    private func makeDialog(title: String, detail: String) -> Object? {
        let dialog = raw(gtk_dialog_new())
        self.dialog = dialog
        let content = raw(gtk_dialog_get_content_area(cast(dialog)))
        // The dialog's one child holds the content and the buttons; it becomes the panel.
        let panel = raw(gtk_bin_get_child(cast(dialog)))
        let body = raw(gtk_box_new(GTK_ORIENTATION_VERTICAL, 16))

        gtk_style_context_add_class(gtk_widget_get_style_context(cast(dialog)), "fm-fido")
        gtk_style_context_add_class(gtk_widget_get_style_context(cast(panel)), "fm-panel")
        // A window with an alpha channel, so that the corners outside the rounded panel are
        // see-through.
        if let visual = raw(gdk_screen_get_rgba_visual(gtk_widget_get_screen(cast(dialog)))) {
            gtk_widget_set_visual(cast(dialog), cast(visual))
        }
        gtk_widget_set_app_paintable(cast(dialog), 1)
        gtk_window_set_title(cast(dialog), "phido2 - Security key")
        // Like Chromium's prompt: no title bar, so no Close button, only Cancel.
        gtk_window_set_decorated(cast(dialog), 0)
        gtk_window_set_keep_above(cast(dialog), 1)
        gtk_window_set_urgency_hint(cast(dialog), 1)
        gtk_window_set_resizable(cast(dialog), 0)
        gtk_window_set_default_size(cast(dialog), 448, -1)

        let focused: @convention(c) (Object?, Object?, Object?) -> gboolean = { widget, _, _ in
            gtk_window_set_urgency_hint(cast(widget), 0)
            return 0  // Let GTK handle the event as well.
        }
        _ = phido2_signal_connect(dialog, "focus-in-event", unsafeBitCast(focused, to: GCallback.self), nil)
        let allocated: @convention(c) (Object?, UnsafeMutablePointer<GdkRectangle>?, Object?) -> Void = { widget, allocation, _ in
            GtkPrompt.position(widget, width: allocation?.pointee.width ?? 0)
        }
        _ = phido2_signal_connect(dialog, "size-allocate", unsafeBitCast(allocated, to: GCallback.self), nil)
        let responded: @convention(c) (Object?, gint, Object?) -> Void = { _, response, context in
            Unmanaged<GtkPrompt>.fromOpaque(context!).takeUnretainedValue().responded(response)
        }
        _ = phido2_signal_connect(dialog, "response", unsafeBitCast(responded, to: GCallback.self), context)
        // Escape and the window manager's close request would destroy the dialog; they are
        // taken as Cancel instead.
        let deleted: @convention(c) (Object?, Object?, Object?) -> gboolean = { _, _, context in
            Unmanaged<GtkPrompt>.fromOpaque(context!).takeUnretainedValue().cancelled()
            return 1  // Handled; do not destroy.
        }
        _ = phido2_signal_connect(dialog, "delete-event", unsafeBitCast(deleted, to: GCallback.self), context)

        gtk_box_pack_start(cast(content), cast(body), 1, 1, 0)
        if let pixbuf = Self.pixbuf(fromPNG: Self.dark ? PackageResources.passkey_usb_dark_png : PackageResources.passkey_usb_png) {
            let image = raw(gtk_image_new_from_pixbuf(cast(pixbuf)))
            g_object_unref(pixbuf)
            gtk_widget_set_margin_top(cast(image), 5)
            gtk_box_pack_start(cast(body), cast(image), 0, 0, 0)
        }
        _ = addLabel(to: body, title, style: "fm-title")
        _ = addLabel(to: body, detail, style: "fm-detail")
        _ = gtk_dialog_add_button(cast(dialog), "Cancel", GTK_RESPONSE_CANCEL.rawValue)
        return body
    }

    /// Adds a left-aligned, wrapping line of text to a box.
    private func addLabel(to box: Object?, _ text: String, style: String) -> Object? {
        let label = raw(gtk_label_new(text))
        gtk_label_set_xalign(cast(label), 0)
        gtk_label_set_line_wrap(cast(label), 1)
        gtk_label_set_max_width_chars(cast(label), 48)
        gtk_style_context_add_class(gtk_widget_get_style_context(cast(label)), style)
        gtk_box_pack_start(cast(box), cast(label), 0, 0, 0)
        return label
    }

    /// Puts the dialog on screen, in front of other windows.
    private func present() {
        gtk_widget_show_all(cast(dialog))
        gtk_window_present(cast(dialog))
    }

    /// Centres the dialog horizontally, a tenth of the screen's height below its top, on the
    /// primary monitor. Called whenever the dialog gets its size.
    private static func position(_ dialog: Object?, width: gint) {
        let display = raw(gtk_widget_get_display(cast(dialog)))
        var monitor = raw(gdk_display_get_primary_monitor(cast(display)))
        if monitor == nil {
            monitor = raw(gdk_display_get_monitor_at_window(cast(display), gtk_widget_get_window(cast(dialog))))
        }
        guard monitor != nil else { return }
        var screen = GdkRectangle()
        gdk_monitor_get_geometry(cast(monitor), &screen)
        gtk_window_move(cast(dialog), screen.x + (screen.width - width) / 2, screen.y + screen.height / 10)
    }

    private var context: Object { Unmanaged.passUnretained(self).toOpaque() }

    // MARK: User actions (main loop)

    /// Enables Next once the PIN field holds a PIN of a valid length.
    private func pinChanged() {
        guard let entry, let dialog else { return }
        let pin = String(cString: gtk_entry_get_text(cast(entry)))
        let valid = pin.count >= Self.minimumPINCharacters && pin.utf8.count <= Self.maximumPINBytes
        gtk_dialog_set_response_sensitive(cast(dialog), GTK_RESPONSE_OK.rawValue, valid ? 1 : 0)
    }

    /// A button of the dialog was pressed.
    private func responded(_ response: gint) {
        guard response == GTK_RESPONSE_OK.rawValue, waitingForPIN, let entry else {
            cancelled()
            return
        }
        answerPIN(String(cString: gtk_entry_get_text(cast(entry))))
    }

    /// Cancel, Escape, or the window manager's close request.
    private func cancelled() {
        if waitingForPIN {
            answerPIN(nil)
        } else if let cancellingLabel {
            // The key is told to stop; the dialog stays until the session has ended.
            gtk_widget_show(cast(cancellingLabel))
            gtk_dialog_set_response_sensitive(cast(dialog), GTK_RESPONSE_CANCEL.rawValue, 0)
            onCancel()
        }
    }

    /// Hands the PIN, or `nil` for a cancelled dialog, to the waiting session.
    private func answerPIN(_ pin: String?) {
        waitingForPIN = false
        pinResult = pin
        close()
        pinAnswered.signal()
    }
}
