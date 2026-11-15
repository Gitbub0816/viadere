import SwiftUI
import ViadereCore
import ViadereKit

/// The production renderer of `PresentationTree` (WP-3.6; plan section 4.4; SECURITY.md §2.92). It draws exactly the nodes it is given,
/// built by `PresentationBuilder` and re-validated by `PresentationRendering.validated` in `LoopInstanceViewModel`:
///
/// * Protected nodes (attribution bar, confirmation panel, outcome status, notices, protected action bars) use Viadere's neutral colors
///   (`ViadereColor`) on their own opaque surfaces; brand tokens style only headers, body text and business action buttons, and the frame
///   is drawn behind everything, so nothing a business supplies can cover or restyle them.
/// * "Built by {name}" is first in reading order with its explicit label (A6a.T5); the verified badge is a separate element.
/// * Every control is a design-system component with Dynamic Type, VoiceOver labels and no timing pressure.
struct PresentationView: View {
    let tree: PresentationTree
    @Bindable var model: LoopInstanceViewModel

    private var brand: BrandStyle { BrandStyle(BrandAppearanceStyle(tree.style)) }

    var body: some View {
        node(tree.root)
            .padding(.vertical, ViadereSpace.m)
            .brandFrameBackground(brand)
    }

    private func node(_ node: PresentationNode) -> AnyView {
        switch node {
        case .screen(let screen):
            return AnyView(VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ForEach(Array(screen.children.enumerated()), id: \.offset) { _, child in self.node(child) }
            }
            .accessibilityElement(children: .contain))
        case .attributionBar(let bar):
            return AnyView(AttributionBarView(bar: bar))
        case .header(let header):
            return AnyView(Text(header.text)
                .font(ViadereType.title)
                .foregroundStyle(brand.onSurface)
                .accessibilityAddTraits(.isHeader))
        case .text(let text):
            return AnyView(Text(text.text)
                .font(ViadereType.body)
                .foregroundStyle(text.role == .secondary ? ViadereColor.textSecondary : ViadereColor.textPrimary)
                .fixedSize(horizontal: false, vertical: true))
        case .fieldGroup(let group):
            return AnyView(VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ForEach(Array(group.children.enumerated()), id: \.offset) { _, child in self.node(child) }
            })
        case .choice(let choice):
            return AnyView(ChoiceFieldView(choice: choice, model: model))
        case .input(let input):
            return AnyView(InputFieldView(input: input, model: model))
        case .actionBar(let bar):
            return AnyView(ActionBarView(bar: bar, model: model, brand: brand))
        case .confirmationPanel(let panel):
            return AnyView(ConfirmationPanelView(panel: panel))
        case .outcomeStatus(let outcome):
            return AnyView(OutcomeStatusView(outcome: outcome))
        case .moduleSlot:
            // First-party modules are not part of a Loop screen.
            return AnyView(EmptyView())
        case .notice(let notice):
            return AnyView(NoticeNodeView(notice: notice))
        }
    }
}

/// "Built by {verified name}" and the separate verified badge. Protected: neutral colors, opaque surface, read first.
private struct AttributionBarView: View {
    let bar: AttributionNode

    var body: some View {
        HStack(spacing: ViadereSpace.xs) {
            Text(bar.text)
                .font(ViadereType.subhead.weight(.semibold))
                .foregroundStyle(BrandStyle.protectedText)
                .lineLimit(2)
                .accessibilityLabel(Text(bar.accessibilityLabel))
                .accessibilitySortPriority(2)
            Spacer(minLength: ViadereSpace.xs)
            if bar.verified {
                ViadereBadge(bar.verifiedLabel, kind: .verified)
                    .accessibilitySortPriority(1)
            }
        }
        .padding(.horizontal, ViadereSpace.m)
        .padding(.vertical, ViadereSpace.s)
        .background(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).fill(BrandStyle.protectedSurface))
        .overlay(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
        .accessibilityElement(children: .contain)
        .accessibilitySortPriority(1000)
    }
}

private struct ChoiceFieldView: View {
    let choice: ChoiceNode
    @Bindable var model: LoopInstanceViewModel

    private var selected: [String] {
        switch model.value(for: choice.fieldId) {
        case .option(let id): [id]
        case .options(let ids): ids
        default: []
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            FieldLabel(text: choice.label, required: choice.required, invalid: model.invalidFields.contains(choice.fieldId))
            ViadereRowGroup {
                ForEach(Array(choice.options.enumerated()), id: \.element.id) { index, option in
                    Button {
                        toggle(option.id)
                    } label: {
                        HStack(spacing: ViadereSpace.s) {
                            Image(systemName: selected.contains(option.id)
                                  ? (choice.multiple ? "checkmark.square.fill" : "largecircle.fill.circle")
                                  : (choice.multiple ? "square" : "circle"))
                                .foregroundStyle(selected.contains(option.id) ? ViadereColor.textPrimary : ViadereColor.textTertiary)
                                .accessibilityHidden(true)
                            Text(option.label).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                            Spacer()
                        }
                        .padding(.vertical, ViadereSpace.s)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .disabled(!model.isActionable)
                    .accessibilityLabel(Text(option.label))
                    .accessibilityAddTraits(selected.contains(option.id) ? [.isButton, .isSelected] : .isButton)
                    if index < choice.options.count - 1 { ViadereHairline() }
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(Text(PresentationRendering.accessibilityLabel(.choice(choice)) ?? choice.label))
    }

    private func toggle(_ id: String) {
        if choice.multiple {
            var ids = selected
            if let index = ids.firstIndex(of: id) { ids.remove(at: index) } else { ids.append(id) }
            // Keep the definition's option order.
            let ordered = choice.options.map(\.id).filter(ids.contains)
            model.set(ordered.isEmpty ? nil : .options(ordered), for: choice.fieldId)
        } else {
            model.set(.option(id), for: choice.fieldId)
        }
    }
}

private struct InputFieldView: View {
    let input: InputNode
    @Bindable var model: LoopInstanceViewModel
    @State private var text = ""
    @State private var date = Date()
    @State private var yesNo: String = ""

    var body: some View {
        let invalid = model.invalidFields.contains(input.fieldId)
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            switch input.input {
            case "short_text":
                ViadereTextField(input.label, text: $text, message: invalid ? "Check this answer." : nil, isError: invalid)
                    .onChange(of: text) { _, value in
                        let limited = String(value.prefix(input.maxLength ?? LoopLimits.maxShortTextLength))
                        if limited != value { text = limited }
                        model.set(limited.isEmpty ? nil : .text(limited), for: input.fieldId)
                    }
                    .disabled(!model.isActionable)
            case "date":
                FieldLabel(text: input.label, required: input.required, invalid: invalid)
                // Stock control: a date picker is necessary here.
                DatePicker(input.label, selection: $date, displayedComponents: .date)
                    .labelsHidden()
                    .tint(ViadereColor.accent)
                    .onChange(of: date, initial: false) { _, value in model.set(.date(LoopFieldValue.dateString(value)), for: input.fieldId) }
                    .disabled(!model.isActionable)
                    .accessibilityLabel(Text(PresentationRendering.accessibilityLabel(.input(input)) ?? input.label))
            case "yes_no":
                FieldLabel(text: input.label, required: input.required, invalid: invalid)
                ViadereSegmented(selection: $yesNo, options: ["yes", "no"]) { $0 == "yes" ? "Yes" : "No" }
                    .onChange(of: yesNo) { _, value in model.set(value.isEmpty ? nil : .flag(value == "yes"), for: input.fieldId) }
                    .disabled(!model.isActionable)
                    .accessibilityLabel(Text(PresentationRendering.accessibilityLabel(.input(input)) ?? input.label))
            case "acknowledgement":
                Toggle(isOn: Binding(get: { model.value(for: input.fieldId) == .flag(true) },
                                     set: { model.set($0 ? .flag(true) : nil, for: input.fieldId) })) {
                    Text(input.label).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                }
                .toggleStyle(.viadere)
                .disabled(!model.isActionable)
            default:
                // Unknown input type: never guess; nothing to fill in.
                EmptyView()
            }
        }
    }
}

private struct FieldLabel: View {
    let text: String
    let required: Bool
    let invalid: Bool

    var body: some View {
        HStack(spacing: 4) {
            Text(text).font(ViadereType.subhead.weight(.semibold)).foregroundStyle(invalid ? ViadereColor.danger : ViadereColor.textPrimary)
            if required { Text("Required").font(ViadereType.caption).foregroundStyle(ViadereColor.textTertiary) }
        }
        .accessibilityElement(children: .combine)
        .accessibilityValue(Text(invalid ? "Needs an answer" : ""))
    }
}

private struct ActionBarView: View {
    let bar: ActionBarNode
    @Bindable var model: LoopInstanceViewModel
    let brand: BrandStyle

    var body: some View {
        VStack(spacing: ViadereSpace.s) {
            ForEach(bar.actions, id: \.id) { action in
                let enabled = action.system || (model.isActionable && !model.isSubmitting)
                Button {
                    Task { await model.perform(action) }
                } label: {
                    Text(action.label)
                }
                .buttonStyle(style(for: action))
                .disabled(!enabled)
                .accessibilityLabel(Text(action.label))
                .accessibilityHint(Text(action.requiresConfirmation ? "Shows what this does before anything is sent" : ""))
            }
        }
    }

    private func style(for action: ActionNode) -> BrandActionButtonStyle {
        BrandActionButtonStyle(role: action.role, brand: bar.protected || action.system ? .neutral : brand)
    }
}

/// Business action buttons: the primary may take the kit's clamped primary color; protected bars and system actions are Viadere's.
private struct BrandActionButtonStyle: ButtonStyle {
    let role: PresentationRole
    let brand: BrandStyle

    func makeBody(configuration: Configuration) -> some View {
        let primary = role == .primary
        configuration.label
            .font(ViadereType.headline)
            .foregroundStyle(primary ? brand.onPrimary : (role == .danger ? ViadereColor.danger : ViadereColor.textPrimary))
            .frame(maxWidth: .infinity, minHeight: 50)
            .background(RoundedRectangle(cornerRadius: ViadereRadius.button, style: .continuous).fill(primary ? brand.primary : ViadereColor.surface))
            .overlay(RoundedRectangle(cornerRadius: ViadereRadius.button, style: .continuous).strokeBorder(primary ? .clear : ViadereColor.hairline, lineWidth: 1))
            .opacity(configuration.isPressed ? 0.85 : 1)
            .animation(ViadereMotion.quick, value: configuration.isPressed)
    }
}

/// The confirmation of a consequential action, naming the responsible business. Protected.
private struct ConfirmationPanelView: View {
    let panel: ConfirmationPanelNode

    var body: some View {
        ViadereCard {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Text(panel.title).font(ViadereType.title).foregroundStyle(BrandStyle.protectedText)
                Text(panel.statement).font(ViadereType.body).foregroundStyle(BrandStyle.protectedText)
                if let amount = panel.amount, !amount.isEmpty {
                    ViadereValueRow("Amount", amount, emphasized: true)
                }
                Text(panel.effect).font(ViadereType.subhead).foregroundStyle(BrandStyle.protectedSecondaryText)
                ViadereHairline()
                ViadereValueRow("Responsible business", panel.responsibleBusinessName)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(panel.accessibilityLabel))
    }
}

/// One of the five outcome states (plan section 4.5), Viadere's words. Protected.
private struct OutcomeStatusView: View {
    let outcome: OutcomeStatusNode

    var body: some View {
        let tone = LoopOutcomeTone(outcome.outcome)
        HStack(alignment: .top, spacing: ViadereSpace.s) {
            Image(systemName: tone.symbol)
                .font(.system(size: 22, weight: .regular))
                .foregroundStyle(tone == .confirmed ? ViadereColor.success : ViadereColor.textSecondary)
                .accessibilityHidden(true)
            Text(outcome.text).font(ViadereType.body).foregroundStyle(BrandStyle.protectedText)
            Spacer(minLength: 0)
        }
        .padding(ViadereSpace.m)
        .background(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).fill(BrandStyle.protectedSurface))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Text(PresentationRendering.accessibilityLabel(.outcomeStatus(outcome)) ?? outcome.text))
    }
}

private struct NoticeNodeView: View {
    let notice: NoticeNode

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            if let title = notice.title {
                Text(title).font(ViadereType.headline).foregroundStyle(BrandStyle.protectedText).accessibilityAddTraits(.isHeader)
            }
            ViadereNotice(notice.text, kind: notice.kind == .healthPrivacy || notice.kind == .unavailable ? .warning : .info)
        }
        .accessibilityElement(children: .combine)
    }
}
