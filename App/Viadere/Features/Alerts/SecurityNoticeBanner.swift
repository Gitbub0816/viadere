import SwiftUI
import ViadereCore
import ViadereKit

/// A calm, high-priority note that something changed on the account. Sits above everything else in Alerts. "This was me" dismisses it;
/// "Review" opens the device list, where anything unfamiliar can be removed. Never red: it asks a question, it does not raise an alarm.
struct SecurityNoticeBanner: View {
    let vm: SecurityNoticesViewModel
    let notice: SecurityNotice
    let review: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            HStack(alignment: .top, spacing: ViadereSpace.s) {
                Image(systemName: "iphone.gen3.badge.exclamationmark")
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(ViadereColor.accent)
                    .padding(.top, 1)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(vm.headline(for: notice))
                        .font(ViadereType.body)
                        .foregroundStyle(ViadereColor.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(vm.prompt(for: notice))
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                    if vm.additionalCount > 0 {
                        Text(vm.additionalCount == 1 ? "1 more notice after this one." : "\(vm.additionalCount) more notices after this one.")
                            .font(ViadereType.subhead)
                            .foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                Spacer(minLength: 0)
            }
            if let message = vm.message {
                ViadereNotice(message, kind: .info)
            }
            // "Not you? Cancel": recovery started, or a new iPhone replacing this one. Needs a device the account already trusts.
            if let title = vm.actionTitle(for: notice) {
                Button(vm.isActing ? "Working…" : title) { Task { await vm.perform(notice) } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(vm.isActing)
                    .accessibilityHint(Text(vm.actionHint(for: notice) ?? ""))
            }
            HStack(spacing: ViadereSpace.s) {
                Button("This was me") { Task { await vm.dismiss(notice) } }
                    .buttonStyle(.viadere(.secondary))
                    .disabled(vm.isDismissing || vm.isActing)
                Button("Review", action: review)
                    .buttonStyle(ViadereButtonStyle(vm.actionTitle(for: notice) == nil ? .primary : .secondary))
            }
        }
        .padding(ViadereSpace.m)
        .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.accent.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).strokeBorder(ViadereColor.accent.opacity(0.3), lineWidth: 1))
        .accessibilityElement(children: .contain)
        .accessibilityAddTraits(.isHeader)
    }
}
