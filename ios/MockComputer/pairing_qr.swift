// Renders the mock computer's pairing text as a QR code PNG (macOS, CoreImage). Used by `mock_computer.py --qr`.
// Usage: swift pairing_qr.swift "<ona-pair:…>" /tmp/out.png
import AppKit
import CoreImage

let args = CommandLine.arguments
guard args.count == 3 else {
    FileHandle.standardError.write(Data("usage: swift pairing_qr.swift <text> <out.png>\n".utf8))
    exit(2)
}
let filter = CIFilter(name: "CIQRCodeGenerator")!
filter.setValue(Data(args[1].utf8), forKey: "inputMessage")
filter.setValue("M", forKey: "inputCorrectionLevel")
let image = filter.outputImage!.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
let rep = NSBitmapImageRep(ciImage: image)
try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: args[2]))
print("QR written to \(args[2])")
