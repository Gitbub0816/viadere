import Foundation

/// Line icons drawn for the site (24 × 24, 1.6 stroke, `currentColor`). No shield shapes, per the brand guide.
/// Used by `{icon:name}` in Markdown and by the showcase components.
public enum Icons {
    static let paths: [String: String] = [
        "key": "<circle cx=\"8\" cy=\"15\" r=\"4\"/><path d=\"M11 12l8.5-8.5M16 7l2.5 2.5M13.5 9.5l2 2\"/>",
        "chip": "<rect x=\"6\" y=\"6\" width=\"12\" height=\"12\" rx=\"2.5\"/><rect x=\"9.5\" y=\"9.5\" width=\"5\" height=\"5\" rx=\"1\"/><path d=\"M9.5 3v3M14.5 3v3M9.5 18v3M14.5 18v3M3 9.5h3M3 14.5h3M18 9.5h3M18 14.5h3\"/>",
        "seal": "<path d=\"M12 2.6l2.2 1.7 2.7-.3 1 2.5 2.5 1-.3 2.7 1.7 2.2-1.7 2.2.3 2.7-2.5 1-1 2.5-2.7-.3L12 21.4l-2.2-1.7-2.7.3-1-2.5-2.5-1 .3-2.7L2.2 12l1.7-2.2-.3-2.7 2.5-1 1-2.5 2.7.3z\"/><path d=\"M8.6 12.2l2.3 2.3 4.6-4.8\"/>",
        "signature": "<path d=\"M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z\"/><path d=\"M14 3v5h5\"/><path d=\"M8.5 16c1.3-2.2 2.4-2.3 3-.4.5 1.7 1.6 1.6 3.6-.6\"/>",
        "split": "<circle cx=\"5\" cy=\"12\" r=\"2.2\"/><circle cx=\"19\" cy=\"5.5\" r=\"2.2\"/><circle cx=\"19\" cy=\"18.5\" r=\"2.2\"/><path d=\"M7.2 12H10c2 0 3-1.2 4.2-3.2l1.6-2.4M10 12c2 0 3 1.2 4.2 3.2l1.6 2.4\"/>",
        "store": "<path d=\"M4.5 10.5V20h15v-9.5\"/><path d=\"M3 9.2L5 4h14l2 5.2a2.6 2.6 0 0 1-4.5 1.8 2.6 2.6 0 0 1-4.5 0 2.6 2.6 0 0 1-4.5 0A2.6 2.6 0 0 1 3 9.2z\"/><path d=\"M10 20v-5h4v5\"/>",
        "phone": "<rect x=\"6.5\" y=\"2.5\" width=\"11\" height=\"19\" rx=\"2.6\"/><path d=\"M10.5 5.2h3\"/>",
        "lock": "<rect x=\"5\" y=\"10.5\" width=\"14\" height=\"10\" rx=\"2.2\"/><path d=\"M8 10.5V7.5a4 4 0 0 1 8 0v3\"/>",
        "eye-off": "<path d=\"M3 3l18 18\"/><path d=\"M10.6 5.1A9.6 9.6 0 0 1 12 5c5 0 8.5 4.5 9.5 7-.4 1-1.2 2.3-2.4 3.5M6.6 6.6C4.6 7.9 3.2 9.9 2.5 12c1 2.5 4.5 7 9.5 7 1.8 0 3.4-.6 4.8-1.4\"/><path d=\"M9.9 9.9a3 3 0 0 0 4.2 4.2\"/>",
        "eye": "<path d=\"M2.5 12c1-2.5 4.5-7 9.5-7s8.5 4.5 9.5 7c-1 2.5-4.5 7-9.5 7s-8.5-4.5-9.5-7z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/>",
        "message": "<path d=\"M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v7a2.5 2.5 0 0 1-2.5 2.5H10l-4.5 4v-4A2.5 2.5 0 0 1 4 13.5z\"/><path d=\"M8.5 9h7M8.5 12h4\"/>",
        "bag": "<path d=\"M5.5 8h13l-1 12.5h-11z\"/><path d=\"M9 10V6.5a3 3 0 0 1 6 0V10\"/>",
        "gift": "<rect x=\"3.5\" y=\"8\" width=\"17\" height=\"4.2\" rx=\"1.2\"/><path d=\"M5 12.2V20h14v-7.8M12 8v12M12 8C11 5 7 4 7 6.5S10.5 8 12 8zm0 0c1-3 5-4 5-1.5S13.5 8 12 8z\"/>",
        "wallet": "<rect x=\"3\" y=\"5.5\" width=\"18\" height=\"14\" rx=\"2.6\"/><path d=\"M3 10h18M15.5 15h2.5\"/>",
        "id": "<rect x=\"3\" y=\"5\" width=\"18\" height=\"14\" rx=\"2.6\"/><circle cx=\"9\" cy=\"11\" r=\"2.1\"/><path d=\"M5.8 16.2c.6-1.5 1.8-2.3 3.2-2.3s2.6.8 3.2 2.3M14.5 10h3.5M14.5 13.5h3.5\"/>",
        "passkey": "<circle cx=\"9\" cy=\"8\" r=\"3.6\"/><path d=\"M3 20c.5-3.6 3-5.6 6-5.6 1.2 0 2.3.3 3.2.9\"/><circle cx=\"17.5\" cy=\"13.8\" r=\"2.3\"/><path d=\"M17.5 16.1V21M17.5 18.6h1.9\"/>",
        "clock": "<circle cx=\"12\" cy=\"12\" r=\"8.5\"/><path d=\"M12 7.5V12l3 2\"/>",
        "arrow": "<path d=\"M5 12h14M13 6l6 6-6 6\"/>",
        "arrow-back": "<path d=\"M19 12H5M11 6l-6 6 6 6\"/>",
        "check": "<path d=\"M5 12.5l4.5 4.5L19 7.5\"/>",
        "x": "<path d=\"M6 6l12 12M18 6L6 18\"/>",
        "faceid": "<path d=\"M4 8.5V6.5A2.5 2.5 0 0 1 6.5 4h2M15.5 4h2A2.5 2.5 0 0 1 20 6.5v2M20 15.5v2a2.5 2.5 0 0 1-2.5 2.5h-2M8.5 20h-2A2.5 2.5 0 0 1 4 17.5v-2\"/><path d=\"M9 9.5v1.2M15 9.5v1.2M12 9.5v3.6h-1M9.6 15.6c1.4 1 3.4 1 4.8 0\"/>",
        "code": "<path d=\"M8.5 7L3.5 12l5 5M15.5 7l5 5-5 5M13.5 5l-3 14\"/>",
        "bolt": "<path d=\"M13 3L5 13.5h6L10 21l8-10.5h-6z\"/>",
        "user": "<circle cx=\"12\" cy=\"8\" r=\"3.6\"/><path d=\"M5 20c.7-3.8 3.6-6 7-6s6.3 2.2 7 6\"/>",
        "sliders": "<path d=\"M4 7h10M18 7h2M4 17h4M12 17h8\"/><circle cx=\"16\" cy=\"7\" r=\"2\"/><circle cx=\"10\" cy=\"17\" r=\"2\"/>",
        "server": "<rect x=\"4\" y=\"4\" width=\"16\" height=\"7\" rx=\"2\"/><rect x=\"4\" y=\"13\" width=\"16\" height=\"7\" rx=\"2\"/><path d=\"M8 7.5h.01M8 16.5h.01M12 7.5h4M12 16.5h4\"/>",
        "repeat": "<path d=\"M17 3l3 3-3 3\"/><path d=\"M4 11V9.5A3.5 3.5 0 0 1 7.5 6H20M7 21l-3-3 3-3\"/><path d=\"M20 13v1.5a3.5 3.5 0 0 1-3.5 3.5H4\"/>",
        "doc": "<path d=\"M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z\"/><path d=\"M14 3v5h5M9 13h6M9 16.5h4\"/>",
        "bell": "<path d=\"M6 16V11a6 6 0 0 1 12 0v5l1.5 2h-15z\"/><path d=\"M10 20.5a2 2 0 0 0 4 0\"/>",
        "globe": "<circle cx=\"12\" cy=\"12\" r=\"8.5\"/><path d=\"M3.5 12h17M12 3.5c2.4 2.4 3.5 5.2 3.5 8.5s-1.1 6.1-3.5 8.5c-2.4-2.4-3.5-5.2-3.5-8.5S9.6 5.9 12 3.5z\"/>",
        "sms": "<path d=\"M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v7a2.5 2.5 0 0 1-2.5 2.5H10l-4.5 4v-4A2.5 2.5 0 0 1 4 13.5z\"/><path d=\"M8.5 10h.01M12 10h.01M15.5 10h.01\"/>",
        "sparkle": "<path d=\"M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8z\"/><path d=\"M18.5 15.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z\"/>",
        "plane": "<path d=\"M10.5 13.5L3 11l1.5-1.5 8 .5 4-4.5c1-1 2.6-1.3 3.2-.7.6.6.3 2.2-.7 3.2l-4.5 4 .5 8L13.5 21 11 13.5\"/>",
        "cup": "<path d=\"M5 8h11v6a5 5 0 0 1-5 5h-1a5 5 0 0 1-5-5z\"/><path d=\"M16 10h1.5a2.5 2.5 0 0 1 0 5H16M8 3.5c-.6 1 .6 1.5 0 2.5M11.5 3.5c-.6 1 .6 1.5 0 2.5\"/>",
        "leaf": "<path d=\"M5 19c0-8 5-13 14-14 0 9-5 14-13 14z\"/><path d=\"M5 19l7.5-7.5\"/>",
        "grape": "<circle cx=\"9\" cy=\"10\" r=\"2.3\"/><circle cx=\"14\" cy=\"10\" r=\"2.3\"/><circle cx=\"11.5\" cy=\"14.2\" r=\"2.3\"/><circle cx=\"11.5\" cy=\"18.5\" r=\"2\"/><path d=\"M11.5 7.5V4M11.5 5c1.5-1.5 3.5-1.5 5-.5\"/>",
        "bank": "<path d=\"M3.5 9.5L12 4l8.5 5.5z\"/><path d=\"M5.5 10v7M10 10v7M14 10v7M18.5 10v7M3.5 20h17\"/>",
    ]

    public static var names: [String] { paths.keys.sorted() }

    /// Decorative icon (hidden from assistive technology). Unknown names render nothing.
    public static func svg(_ name: String, cls: String = "ic") -> String {
        guard let p = paths[name] else { return "" }
        return "<svg class=\"\(cls) ic-\(name)\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.6\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\" focusable=\"false\">\(p)</svg>"
    }

    /// The filled "verified business" seal shown next to business names in the mockups.
    public static func verifiedSeal(_ cls: String = "vseal") -> String {
        "<svg class=\"\(cls)\" viewBox=\"0 0 24 24\" aria-hidden=\"true\" focusable=\"false\"><path fill=\"currentColor\" d=\"M12 1.8l2.4 1.8 3-.3 1.1 2.8 2.8 1.1-.3 3 1.8 2.4-1.8 2.4.3 3-2.8 1.1-1.1 2.8-3-.3L12 22.2l-2.4-1.8-3 .3-1.1-2.8-2.8-1.1.3-3L1.2 12.4 3 10l-.3-3 2.8-1.1L6.6 3.1l3 .3z\"/><path d=\"M8.3 12.3l2.5 2.5 5-5.2\" class=\"vseal-check\" fill=\"none\" stroke=\"#fff\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg>"
    }
}
