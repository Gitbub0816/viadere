import SwiftUI
import UIKit
import ViadereKit

/// The number field of the push-approval screen and the device-add screen (ADR-0022 §2.3, A6/A7 finding 15; `NumberFieldTraits.required`).
///
/// Everything that could fill the field for the person is turned off: no `textContentType` (so no one-time-code, password or contact
/// suggestions), no QuickType bar, no paste, no drag-and-drop, no selection or edit menu, no autocorrection, never prefilled. The text field
/// never changes itself: each keystroke is handed to the Kit (`NumberMatcher.applyEdit`), which refuses a paste or a replacement, and the
/// field shows whatever the model holds. A wrong entry is announced to VoiceOver by the caller, not shown by colour alone.
struct NumberEntryField: UIViewRepresentable {
    let text: String
    let accessibilityLabel: String
    let onEdit: (String) -> Void

    func makeUIView(context: Context) -> NoPasteTextField {
        let field = NoPasteTextField()
        field.delegate = context.coordinator
        field.keyboardType = .numberPad
        field.textContentType = nil
        field.autocorrectionType = .no
        field.spellCheckingType = .no
        field.autocapitalizationType = .none
        field.smartDashesType = .no
        field.smartQuotesType = .no
        field.smartInsertDeleteType = .no
        field.inputAssistantItem.leadingBarButtonGroups = []
        field.inputAssistantItem.trailingBarButtonGroups = []
        field.pasteConfiguration = UIPasteConfiguration(acceptableTypeIdentifiers: [])
        field.textDragInteraction?.isEnabled = false
        field.clearButtonMode = .never
        field.textAlignment = .center
        field.font = UIFont.monospacedDigitSystemFont(ofSize: 34, weight: .semibold)
        field.adjustsFontForContentSizeCategory = true
        field.isAccessibilityElement = true
        field.accessibilityLabel = accessibilityLabel
        field.setContentHuggingPriority(.defaultLow, for: .horizontal)
        return field
    }

    func updateUIView(_ field: NoPasteTextField, context: Context) {
        if field.text != text { field.text = text }
        field.accessibilityLabel = accessibilityLabel
        context.coordinator.onEdit = onEdit
    }

    func makeCoordinator() -> Coordinator { Coordinator(onEdit: onEdit) }

    final class Coordinator: NSObject, UITextFieldDelegate {
        var onEdit: (String) -> Void
        init(onEdit: @escaping (String) -> Void) { self.onEdit = onEdit }

        func textField(_ textField: UITextField, shouldChangeCharactersIn range: NSRange, replacementString string: String) -> Bool {
            let current = textField.text ?? ""
            guard let swiftRange = Range(range, in: current) else { return false }
            onEdit(current.replacingCharacters(in: swiftRange, with: string))
            // The model owns the text; `updateUIView` writes it back.
            return false
        }
    }
}

/// A text field that offers no edit menu at all (no paste, copy, cut, select, replace or lookup).
final class NoPasteTextField: UITextField {
    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool { false }
    override func paste(_ sender: Any?) {}
    override func buildMenu(with builder: any UIMenuBuilder) {
        builder.remove(menu: .standardEdit)
        builder.remove(menu: .lookup)
        builder.remove(menu: .replace)
        super.buildMenu(with: builder)
    }
}
