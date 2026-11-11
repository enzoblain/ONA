// Draws the ONA logo (concentric rings: the O of ONA, the layers of the onion, you at the centre) and writes every
// app icon from it: iOS, macOS and the Tauri app. Run from the repository root: swift assets/make_icons.swift
import AppKit
import CoreGraphics
import Foundation

enum Shape {
    /// Full square: iOS masks the corners itself.
    case square
    /// macOS icon grid: 824/1024 rounded rectangle, centred.
    case macOS
    /// Rounded square with a thin margin (Windows, Linux).
    case rounded
}

func color(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255,
            blue: CGFloat(hex & 0xff) / 255, alpha: alpha)
}

func draw(size: Int, shape: Shape) -> Data {
    let s = CGFloat(size)
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let opaque = shape == .square
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                        bitmapInfo: opaque ? CGImageAlphaInfo.noneSkipLast.rawValue
                                           : CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.interpolationQuality = .high

    // Tile of the icon, in a 1024 grid.
    let tile: CGRect
    let radius: CGFloat
    switch shape {
    case .square: tile = CGRect(x: 0, y: 0, width: 1024, height: 1024); radius = 0
    case .macOS: tile = CGRect(x: 100, y: 100, width: 824, height: 824); radius = 185
    case .rounded: tile = CGRect(x: 40, y: 40, width: 944, height: 944); radius = 208
    }
    ctx.scaleBy(x: s / 1024, y: s / 1024)
    let path = CGPath(roundedRect: tile, cornerWidth: radius, cornerHeight: radius, transform: nil)

    // Background: deep indigo gradient, lighter at the top.
    ctx.saveGState()
    ctx.addPath(path)
    ctx.clip()
    let gradient = CGGradient(colorsSpace: space, colors: [color(0x2A2F63), color(0x0E1024)] as CFArray,
                              locations: [0, 1])!
    ctx.drawLinearGradient(gradient, start: CGPoint(x: 512, y: tile.maxY), end: CGPoint(x: 512, y: tile.minY),
                           options: [])
    ctx.restoreGState()

    // The rings scale with the tile.
    let k = tile.width / 1024
    let c = CGPoint(x: 512, y: 512)
    func ring(_ r: CGFloat, _ width: CGFloat, _ fill: CGColor) {
        ctx.setStrokeColor(fill)
        ctx.setLineWidth(width * k)
        ctx.strokeEllipse(in: CGRect(x: c.x - r * k, y: c.y - r * k, width: 2 * r * k, height: 2 * r * k))
    }
    ring(300, 84, color(0xF3F4FA))
    ring(168, 40, color(0x8FA2FF))
    ctx.setFillColor(color(0xF3F4FA))
    ctx.fillEllipse(in: CGRect(x: c.x - 44 * k, y: c.y - 44 * k, width: 88 * k, height: 88 * k))

    let image = ctx.makeImage()!
    let rep = NSBitmapImageRep(cgImage: image)
    return rep.representation(using: .png, properties: [:])!
}

func write(_ data: Data, _ path: String) {
    let url = URL(fileURLWithPath: path)
    try! FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try! data.write(to: url)
}

func json(_ object: Any, _ path: String) {
    let data = try! JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
    write(data + Data("\n".utf8), path)
}

/// ICO holding PNG images (Windows Vista and later).
func ico(_ images: [(Int, Data)]) -> Data {
    var out = Data()
    func u16(_ v: Int) { var x = UInt16(v).littleEndian; out.append(Data(bytes: &x, count: 2)) }
    func u32(_ v: Int) { var x = UInt32(v).littleEndian; out.append(Data(bytes: &x, count: 4)) }
    u16(0); u16(1); u16(images.count)
    var offset = 6 + 16 * images.count
    for (size, png) in images {
        out.append(UInt8(size >= 256 ? 0 : size)); out.append(UInt8(size >= 256 ? 0 : size))
        out.append(0); out.append(0); u16(1); u16(32); u32(png.count); u32(offset)
        offset += png.count
    }
    for (_, png) in images { out.append(png) }
    return out
}

let info = ["author": "xcode", "version": 1] as [String: Any]

// iOS: one 1024 icon, opaque.
let ios = "ios/ONA/ONA/Assets.xcassets"
json(["info": info], "\(ios)/Contents.json")
write(draw(size: 1024, shape: .square), "\(ios)/AppIcon.appiconset/AppIcon.png")
json(["images": [["filename": "AppIcon.png", "idiom": "universal", "platform": "ios", "size": "1024x1024"]],
      "info": info], "\(ios)/AppIcon.appiconset/Contents.json")

// macOS: every size of the icon grid.
let mac = "desktop/ONADesktop/App/Assets.xcassets"
json(["info": info], "\(mac)/Contents.json")
var macImages: [[String: String]] = []
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        write(draw(size: points * scale, shape: .macOS), "\(mac)/AppIcon.appiconset/\(name)")
        macImages.append(["filename": name, "idiom": "mac", "scale": "\(scale)x", "size": "\(points)x\(points)"])
    }
}
json(["images": macImages, "info": info], "\(mac)/AppIcon.appiconset/Contents.json")

// Tauri (Windows, Linux).
let tauri = "desktop/tauri/src-tauri/icons"
let png = Dictionary(uniqueKeysWithValues: [16, 24, 32, 48, 64, 128, 256, 512].map { ($0, draw(size: $0, shape: .rounded)) })
write(png[32]!, "\(tauri)/32x32.png")
write(png[128]!, "\(tauri)/128x128.png")
write(png[256]!, "\(tauri)/128x128@2x.png")
write(png[512]!, "\(tauri)/icon.png")
write(ico([16, 24, 32, 48, 64, 256].map { ($0, png[$0]!) }), "\(tauri)/icon.ico")

// Large preview for the README.
write(draw(size: 512, shape: .rounded), "assets/logo.png")
print("icons written")
