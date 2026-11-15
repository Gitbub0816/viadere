import Foundation
import ViadereBusinessSDK
import ViadereCore

// viadere-key-monitor: audits the transparency-log entries of your business.
//
//   VIADERE_API_KEY=vdk_live_... viadere-key-monitor --business <uuid> --log-key <base64url P-256 public key> \
//       --state monitor-state.json [--base-url https://viadere.com] [--log-id viadere.key-directory.v1]
//
// It verifies the signed tree head, the consistency with the head it saw last time, every inclusion proof and the replayed key history,
// then lists new entries. `--state` is a JSON file holding the last head, the indexes already reviewed and the leaf hashes of the entries you
// published (add yours with `--expect <hex leaf hash>`). Exit codes: 0 all entries expected, 2 an unexpected entry or a failed
// verification (treat as an incident), 64 usage.

struct MonitorState: Codable {
    var seen: SeenTreeHead?
    var reviewed: Set<Int> = []
    var expected: Set<String> = []
}

func fail(_ message: String, code: Int32) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(code)
}

let arguments = Array(CommandLine.arguments.dropFirst())
func option(_ name: String) -> String? {
    guard let index = arguments.firstIndex(of: name), index + 1 < arguments.count else { return nil }
    return arguments[index + 1]
}
let expectations = arguments.enumerated().filter { $0.element == "--expect" }.compactMap { arguments.indices.contains($0.offset + 1) ? arguments[$0.offset + 1] : nil }

guard let apiKey = ProcessInfo.processInfo.environment["VIADERE_API_KEY"], let businessText = option("--business"), let business = BusinessID(businessText),
      let logKeyText = option("--log-key"), let logKey = try? DevicePublicKey(base64URL: logKeyText) else {
    fail("usage: VIADERE_API_KEY=... viadere-key-monitor --business <uuid> --log-key <base64url> --state <file> [--base-url URL] [--log-id ID] [--expect <leaf hash>]...", code: 64)
}
let baseURL = URL(string: option("--base-url") ?? "https://viadere.com")!
let logId = option("--log-id") ?? TransparencyLog.defaultLogId
let statePath = option("--state")

var state = MonitorState()
if let statePath, let data = FileManager.default.contents(atPath: statePath) {
    guard let loaded = try? JSONDecoder().decode(MonitorState.self, from: data) else { fail("cannot read the state file \(statePath)", code: 64) }
    state = loaded
}
state.expected.formUnion(expectations)

do {
    let client = try ViadereBusinessClient(apiKey: apiKey, baseURL: baseURL)
    let response = try await client.keyDirectoryEntries(since: state.seen?.treeSize)
    let report = try KeyLogMonitor(businessId: business, logKeys: [logKey], logId: logId)
        .check(response, lastSeen: state.seen, knownIndexes: state.reviewed, expected: state.expected)
    print("tree size \(report.treeSize), root \(report.rootKid ?? "none"), \(report.newEntries.count) new entries")
    for entry in report.newEntries {
        let flag = report.unexpected.contains(entry) ? "UNEXPECTED" : "expected"
        print("\(flag) index=\(entry.index) type=\(entry.type) kid=\(entry.kid ?? "-") leaf=\(entry.leafHash)")
    }
    if report.unexpected.isEmpty {
        state.seen = report.seen
        state.reviewed.formUnion(report.newEntries.map(\.index))
        if let statePath { try JSONEncoder().encode(state).write(to: URL(fileURLWithPath: statePath), options: .atomic) }
        exit(0)
    }
    // An unexpected entry is not marked reviewed: the alert repeats until someone deals with it.
    fail("ALERT: \(report.unexpected.count) log entries for this business were not made by you.", code: 2)
} catch {
    fail("ALERT: verification failed: \(error)", code: 2)
}
