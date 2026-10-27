import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

/// A QR code for a redemption code, drawn from the server's string (error correction M). Always dark modules on a
/// white plate, in light and dark mode, so counter scanners can read it.
struct QRCodeView: View {
    let payload: String
    var size: CGFloat = 188

    var body: some View {
        Group {
            if let image = Self.render(payload) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .frame(width: size, height: size)
            } else {
                Image(systemName: "qrcode").font(.system(size: 64, weight: .ultraLight)).foregroundStyle(ViadereColor.textTertiary)
                    .frame(width: size, height: size)
            }
        }
        .padding(ViadereSpace.m)
        .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(Color.white))
        .overlay(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
        .accessibilityLabel(Text("QR code for the business to scan"))
    }

    private static let context = CIContext()

    static func render(_ string: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        guard let cgImage = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: cgImage)
    }
}
