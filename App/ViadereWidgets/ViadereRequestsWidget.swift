import SwiftUI
import ViadereKit
import WidgetKit

/// The Home Screen widget (small and medium): how many requests wait, and in the medium size how many benefits are available. Nothing
/// else. The app writes only numbers and times to the app group (`WidgetSnapshot`, ViadereKit, tested); no business name, request type,
/// amount, code or message text can reach this process. The wording and the timeline (the count drops as each request expires, and the
/// face goes neutral when the snapshot is a day old) come from `WidgetEntryContent` and `WidgetTimelineModel`; this file only lays it out.
///
/// A tap opens the app (no `widgetURL`: there is no deep link for the Alerts list, and the widget adds none). Brand: charcoal, ivory,
/// champagne and the ribbon mark; light, dark and tinted (accented) rendering; no shield imagery.
struct ViadereRequestsWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: WidgetSnapshot.kind, provider: RequestsTimelineProvider()) { entry in
            RequestsWidgetView(entry: entry)
        }
        .configurationDisplayName("Requests")
        .description("How many requests wait for you. No names or details.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

struct RequestsWidgetEntry: TimelineEntry {
    let date: Date
    let content: WidgetEntryContent
    /// The gallery and loading placeholder: the layout with no figure, drawn redacted.
    var isPlaceholder = false
}

struct RequestsTimelineProvider: TimelineProvider {
    private static var store: WidgetSnapshotStore {
        WidgetSnapshotStore(persistence: UserDefaultsWidgetSnapshotPersistence(suiteName: ViadereThemeRuntime.appGroupID))
    }

    func placeholder(in context: Context) -> RequestsWidgetEntry {
        RequestsWidgetEntry(date: Date(), content: .placeholder(date: Date()), isPlaceholder: true)
    }

    func getSnapshot(in context: Context, completion: @escaping (RequestsWidgetEntry) -> Void) {
        let now = Date()
        // The gallery shows the neutral face, never the person's numbers.
        let content = context.isPreview ? WidgetEntryContent.placeholder(date: now) : WidgetEntryContent(date: now, snapshot: Self.store.read())
        completion(RequestsWidgetEntry(date: now, content: content))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<RequestsWidgetEntry>) -> Void) {
        let now = Date()
        let entries = WidgetTimelineModel.entries(snapshot: Self.store.read(), now: now).map { RequestsWidgetEntry(date: $0.date, content: $0) }
        // After the last entry (the neutral face) nothing changes until the app writes again and asks for a reload.
        completion(Timeline(entries: entries, policy: .never))
    }
}

struct RequestsWidgetView: View {
    let entry: RequestsWidgetEntry
    @Environment(\.widgetFamily) private var family
    @Environment(\.widgetRenderingMode) private var renderingMode

    private var content: WidgetEntryContent { entry.content }
    private var tinted: Bool { renderingMode != .fullColor }

    var body: some View {
        Group {
            if family == .systemMedium { medium } else { small }
        }
        .redacted(reason: entry.isPlaceholder ? .placeholder : [])
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(content.accessibilityLabel)
        .containerBackground(for: .widget) { ViadereColor.background }
    }

    private var small: some View {
        VStack(alignment: .leading, spacing: 0) {
            mark
            Spacer(minLength: 0)
            figure
            Text(content.headline)
                .font(ViadereType.subhead)
                .foregroundStyle(ViadereColor.textSecondary)
                .lineLimit(2)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
    }

    private var medium: some View {
        HStack(alignment: .center, spacing: 16) {
            VStack(alignment: .leading, spacing: 0) {
                mark
                Spacer(minLength: 0)
                figure
                Text(content.headline)
                    .font(ViadereType.subhead)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .lineLimit(2)
            }
            Spacer(minLength: 0)
            if let benefits = content.benefitsLine {
                VStack(alignment: .trailing, spacing: 6) {
                    Spacer(minLength: 0)
                    // A short champagne keyline: the brand accent, used sparingly.
                    Capsule().fill(ViadereColor.accent).frame(width: 24, height: 3).widgetAccentable()
                    Text(benefits)
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textPrimary)
                        .multilineTextAlignment(.trailing)
                        .lineLimit(2)
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// The ribbon mark: full colour by day and night, one flat tone when the Home Screen is tinted.
    @ViewBuilder private var mark: some View {
        Group {
            if tinted { ViadereMark.monochrome(.white) } else { ViadereMark(style: .automatic) }
        }
        .frame(height: 22)
        .widgetAccentable()
        .accessibilityHidden(true)
    }

    /// The count of waiting requests (absent when nothing waits or nothing is known).
    @ViewBuilder private var figure: some View {
        if let count = content.count {
            Text(count)
                .font(ViadereType.display)
                .foregroundStyle(ViadereColor.textPrimary)
                .monospacedDigit()
                .contentTransition(.numericText())
                .privacySensitive()
        }
    }
}
