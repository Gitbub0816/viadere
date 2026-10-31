// Sends one test push straight to APNs (sandbox) from a Mac, for a Debug or Staging build. Swift + CryptoKit only.
//
//   swift App/Scripts/apns-send.swift --key ~/secrets/AuthKey_NH9V2KR4LK.p8 --token <device token hex> \
//       [--title "Viadere"] [--body "Test notification"] [--subtitle ""] [--category ""] [--production]
//
// The device token is printed in Xcode's console (event `push.token.sandbox`) when the app runs from Xcode with notifications allowed.
// The key file never leaves the Mac; the signed JWT is used for this one request and not printed. Team M669H43X63, key NH9V2KR4LK,
// topic com.viadere.app (override with --team, --key-id, --topic).
import CryptoKit
import Foundation

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("error: \(message)\n".utf8))
    exit(1)
}

var options: [String: String] = ["team": "M669H43X63", "key-id": "NH9V2KR4LK", "topic": "com.viadere.app",
                                 "title": "Viadere", "body": "Test notification", "subtitle": "", "category": ""]
var production = false
var arguments = CommandLine.arguments.dropFirst()
while let argument = arguments.popFirst() {
    guard argument.hasPrefix("--") else { fail("unexpected argument \(argument)") }
    let name = String(argument.dropFirst(2))
    if name == "production" { production = true; continue }
    guard let value = arguments.popFirst() else { fail("--\(name) needs a value") }
    options[name] = value
}
guard let keyPath = options["key"] else { fail("--key <AuthKey_*.p8> is required") }
guard let token = options["token"]?.lowercased().filter({ !$0.isWhitespace && $0 != "<" && $0 != ">" }),
      token.count >= 64, token.count <= 200, token.allSatisfy(\.isHexDigit) else { fail("--token must be the device token in hex") }

func base64url(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

let pem: String
do { pem = try String(contentsOfFile: (keyPath as NSString).expandingTildeInPath, encoding: .utf8) } catch { fail("cannot read \(keyPath)") }
let key: P256.Signing.PrivateKey
do { key = try P256.Signing.PrivateKey(pemRepresentation: pem) } catch { fail("\(keyPath) is not an APNs .p8 key") }

let header = base64url(try JSONSerialization.data(withJSONObject: ["alg": "ES256", "kid": options["key-id"]!], options: [.sortedKeys]))
let claims = base64url(try JSONSerialization.data(withJSONObject: ["iss": options["team"]!, "iat": Int(Date().timeIntervalSince1970)],
                                                   options: [.sortedKeys]))
let signingInput = "\(header).\(claims)"
let signature = try key.signature(for: Data(signingInput.utf8))
let jwt = "\(signingInput).\(base64url(signature.rawRepresentation))"

var alert: [String: String] = ["title": options["title"]!, "body": options["body"]!]
if let subtitle = options["subtitle"], !subtitle.isEmpty { alert["subtitle"] = subtitle }
var aps: [String: Any] = ["alert": alert, "sound": "default"]
if let category = options["category"], !category.isEmpty { aps["category"] = category }
let payload = try JSONSerialization.data(withJSONObject: ["aps": aps])

let host = production ? "api.push.apple.com" : "api.sandbox.push.apple.com"
var request = URLRequest(url: URL(string: "https://\(host)/3/device/\(token)")!)
request.httpMethod = "POST"
request.httpBody = payload
request.setValue("bearer \(jwt)", forHTTPHeaderField: "authorization")
request.setValue(options["topic"]!, forHTTPHeaderField: "apns-topic")
request.setValue("alert", forHTTPHeaderField: "apns-push-type")
request.setValue("10", forHTTPHeaderField: "apns-priority")

let (data, response) = try await URLSession.shared.data(for: request)
let status = (response as? HTTPURLResponse)?.statusCode ?? 0
let apnsID = (response as? HTTPURLResponse)?.value(forHTTPHeaderField: "apns-id") ?? "-"
if status == 200 {
    print("sent (\(host), apns-id \(apnsID))")
} else {
    print("APNs refused it: HTTP \(status) \(String(data: data, encoding: .utf8) ?? "")")
    print("BadDeviceToken: the token is from the other environment (Debug/Staging builds are sandbox) or from another app install.")
    exit(2)
}
