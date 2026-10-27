import Foundation
import SiteKit

// Usage: viadere-site [build|check-links|update-legal-lock] [--root DIR] [--out DIR] [--repo DIR]
let allArgs = Array(CommandLine.arguments.dropFirst())
let command = allArgs.first.flatMap { $0.hasPrefix("-") ? nil : $0 } ?? "build"
let args = allArgs.first.map { $0.hasPrefix("-") } == false ? Array(allArgs.dropFirst()) : allArgs

func value(_ flag: String) -> String? {
    guard let i = args.firstIndex(of: flag), i + 1 < args.count else { return nil }
    return args[i + 1]
}

let fm = FileManager.default
let cwd = URL(fileURLWithPath: fm.currentDirectoryPath)
var root: URL
if let r = value("--root") { root = URL(fileURLWithPath: r, relativeTo: cwd) }
else if fm.fileExists(atPath: cwd.appendingPathComponent("content").path) { root = cwd }
else { root = cwd.appendingPathComponent("Site") }
root = root.standardizedFileURL

var options = BuildOptions(siteRoot: root)
if let o = value("--out") { options.outDir = URL(fileURLWithPath: o, relativeTo: cwd).standardizedFileURL }
if let r = value("--repo") { options.repoRoot = URL(fileURLWithPath: r, relativeTo: cwd).standardizedFileURL }

do {
    switch command {
    case "build", "update-legal-lock":
        options.updateLegalLock = command == "update-legal-lock"
        let report = try SiteBuilder(options: options).build()
        for f in report.findings where f.severity == .warning { print(f.description) }
        for w in report.warnings { print("[warning] \(w)") }
        if report.ok {
            print("Built \(report.pages.count) pages, \(report.fileCount) files into \(options.outDir.path)")
            print("Integrity lint, output policy and link check passed.")
        } else {
            FileHandle.standardError.write(Data("Build FAILED with \(report.errors.count) problem(s):\n".utf8))
            for e in report.errors { FileHandle.standardError.write(Data("  \(e)\n".utf8)) }
            exit(1)
        }
    case "check-links":
        let problems = LinkChecker.check(dist: options.outDir) + OutputChecker.check(dist: options.outDir, config: try SiteConfig.load(from: root.appendingPathComponent("site.yaml")))
        if problems.isEmpty { print("No broken links or policy violations in \(options.outDir.path)") }
        else { for p in problems { FileHandle.standardError.write(Data("\(p)\n".utf8)) }; exit(1) }
    default:
        FileHandle.standardError.write(Data("Unknown command \(command). Use build, check-links or update-legal-lock.\n".utf8))
        exit(2)
    }
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n".utf8))
    exit(1)
}
