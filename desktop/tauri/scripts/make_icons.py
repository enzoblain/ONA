"""Draws the app icon (a ring on a dark rounded square) as PNG and ICO files, with the standard library only.

Run from desktop/tauri: python3 scripts/make_icons.py
"""
import math
import struct
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src-tauri" / "icons"


def pixel(x, y, size):
    """RGBA of one pixel, with 4x4 supersampling for smooth edges."""
    total = [0.0, 0.0, 0.0, 0.0]
    for sx in range(4):
        for sy in range(4):
            u = (x + (sx + 0.5) / 4) / size
            v = (y + (sy + 0.5) / 4) / size
            # Rounded square, corner radius 22 %.
            r = 0.22
            dx = max(abs(u - 0.5) - (0.5 - r), 0)
            dy = max(abs(v - 0.5) - (0.5 - r), 0)
            if math.hypot(dx, dy) > r:
                continue
            d = math.hypot(u - 0.5, v - 0.5)
            ring = 0.20 <= d <= 0.30
            color = (245, 245, 247) if ring else (28, 30, 38)
            total[0] += color[0]
            total[1] += color[1]
            total[2] += color[2]
            total[3] += 255
    return tuple(round(c / 16) for c in total)


def png(size):
    rows = b""
    for y in range(size):
        rows += b"\x00" + b"".join(bytes(pixel(x, y, size)) for x in range(size))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(rows, 9)) + chunk(b"IEND", b"")


def ico(images):
    """ICO file holding PNG images (supported since Windows Vista)."""
    head = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, data = b"", b""
    for size, image in images:
        dim = 0 if size >= 256 else size
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(image), offset + len(data))
        data += image
    return head + entries + data


OUT.mkdir(parents=True, exist_ok=True)
images = {size: png(size) for size in (32, 128, 256, 512)}
(OUT / "32x32.png").write_bytes(images[32])
(OUT / "128x128.png").write_bytes(images[128])
(OUT / "128x128@2x.png").write_bytes(images[256])
(OUT / "icon.png").write_bytes(images[512])
(OUT / "icon.ico").write_bytes(ico([(32, images[32]), (256, images[256])]))
print("icons written to", OUT)
