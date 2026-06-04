"""
NovaSentinel — Professional Asset Generator
Generates all branding assets using Pillow only (no external fonts needed).
Colors: Crimson Night theme — bg #0F0A0A, accent #FF3E3E, surface #1A1414

Usage:
    python scripts/generate_assets.py
"""

import os
import math
import sys

try:
    from PIL import Image, ImageDraw, ImageFilter, ImageFont
except ImportError:
    print("[ERROR] Pillow not installed. Run: pip install Pillow")
    sys.exit(1)

# ── Directories ───────────────────────────────────────────────────────────────
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
ASSETS_DIR = os.path.join(ROOT_DIR, "assets")
os.makedirs(ASSETS_DIR, exist_ok=True)

# ── Color Palette (Crimson Night) ─────────────────────────────────────────────
BG       = (15, 10, 10)        # #0F0A0A
SURFACE  = (26, 20, 20)        # #1A1414
ACCENT   = (255, 62, 62)       # #FF3E3E
ACCENT2  = (200, 30, 30)       # #C81E1E
TEXT     = (245, 230, 230)     # #F5E6E6
BORDER   = (46, 35, 35)        # #2E2323
GLOW     = (255, 80, 80, 80)   # semi-transparent red glow
DARK_RED = (80, 15, 15)        # for grid lines


def _hex_points(cx, cy, r):
    """Return 6 points of a hexagon centred at (cx, cy) with radius r."""
    pts = []
    for i in range(6):
        angle = math.radians(60 * i - 30)
        pts.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))
    return pts


def _draw_hex_grid(draw, w, h, spacing=48, alpha=18):
    """Draw a subtle hexagonal grid pattern."""
    color = (*DARK_RED, alpha)
    for row in range(-1, h // spacing + 2):
        for col in range(-1, w // spacing + 2):
            cx = col * spacing * 1.732
            cy = row * spacing * 2 + (col % 2) * spacing
            pts = _hex_points(cx, cy, spacing * 0.9)
            draw.polygon(pts, outline=color, fill=None)


def _draw_shield(draw, cx, cy, size, fill_outer, fill_inner, accent):
    """Draw a geometric pentagon-shield."""
    # Outer shield
    s = size
    outer = [
        (cx, cy - s * 0.85),           # top center
        (cx + s * 0.75, cy - s * 0.4), # top right
        (cx + s * 0.75, cy + s * 0.25),# mid right
        (cx, cy + s * 0.90),           # bottom point
        (cx - s * 0.75, cy + s * 0.25),# mid left
        (cx - s * 0.75, cy - s * 0.4), # top left
    ]
    draw.polygon(outer, fill=fill_outer)

    # Inner shield (inset)
    margin = s * 0.12
    inner = [
        (cx, cy - s * 0.72),
        (cx + s * 0.62, cy - s * 0.3),
        (cx + s * 0.62, cy + s * 0.22),
        (cx, cy + s * 0.78),
        (cx - s * 0.62, cy + s * 0.22),
        (cx - s * 0.62, cy - s * 0.3),
    ]
    draw.polygon(inner, fill=fill_inner)

    # Accent border on outer
    draw.line(outer + [outer[0]], fill=accent, width=max(2, int(s * 0.035)))


def _draw_neural_eye(draw, cx, cy, r, accent):
    """Draw an AI 'neural eye' — iris + pupil + radiating lines."""
    # Outer glow ring
    for g in range(5, 0, -1):
        alpha = int(60 / g)
        color = (*accent[:3], alpha)
        rg = r + g * 4
        draw.ellipse((cx - rg, cy - rg, cx + rg, cy + rg), outline=color, width=1)

    # Iris
    draw.ellipse((cx - r, cy - r, cx + r, cy + r), fill=SURFACE, outline=accent[:3], width=max(2, int(r * 0.12)))

    # Pupil
    pr = int(r * 0.4)
    draw.ellipse((cx - pr, cy - pr, cx + pr, cy + pr), fill=accent[:3])

    # Neural spokes radiating from iris
    num_spokes = 8
    for i in range(num_spokes):
        angle = math.radians(360 / num_spokes * i)
        x1 = cx + (pr + 4) * math.cos(angle)
        y1 = cy + (pr + 4) * math.sin(angle)
        x2 = cx + (r - 2) * math.cos(angle)
        y2 = cy + (r - 2) * math.sin(angle)
        draw.line([(x1, y1), (x2, y2)], fill=(*accent[:3], 180), width=max(1, int(r * 0.06)))

    # Highlight reflection
    hr = max(2, int(r * 0.15))
    hx, hy = cx - int(r * 0.25), cy - int(r * 0.25)
    draw.ellipse((hx - hr, hy - hr, hx + hr, hy + hr), fill=(255, 200, 200, 160))


def _draw_circuit_lines(draw, cx, cy, shield_size, accent, num=6):
    """Draw small circuit traces emanating from shield edges."""
    for i in range(num):
        angle = math.radians(360 / num * i + 15)
        start_r = shield_size * 0.75
        sx = cx + start_r * math.cos(angle)
        sy = cy + start_r * math.sin(angle)
        ex = cx + (start_r + shield_size * 0.25) * math.cos(angle)
        ey = cy + (start_r + shield_size * 0.25) * math.sin(angle)
        # L-shaped trace
        mid_x = ex if i % 2 == 0 else sx
        mid_y = sy if i % 2 == 0 else ey
        draw.line([(sx, sy), (mid_x, mid_y), (ex, ey)], fill=(*accent[:3], 120), width=max(1, int(shield_size * 0.025)))
        # Terminal dot
        dot_r = max(2, int(shield_size * 0.025))
        draw.ellipse((ex - dot_r, ey - dot_r, ex + dot_r, ey + dot_r), fill=(*accent[:3], 160))


def build_logo_image(size=512):
    """Build the main NovaSentinel logo at given size."""
    img = Image.new("RGBA", (size, size), (*BG, 255))
    overlay = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    cx, cy = size // 2, size // 2
    shield_size = int(size * 0.40)
    eye_radius = int(shield_size * 0.30)

    # Background hex grid
    _draw_hex_grid(draw, size, size, spacing=int(size * 0.09), alpha=15)

    # Circuit decoration
    _draw_circuit_lines(draw, cx, cy, shield_size, ACCENT, num=8)

    # Shield
    _draw_shield(draw, cx, cy, shield_size,
                 fill_outer=(30, 10, 10),
                 fill_inner=(20, 8, 8),
                 accent=ACCENT)

    # Neural eye
    _draw_neural_eye(draw, cx, cy, eye_radius, ACCENT)

    img = Image.alpha_composite(img, overlay)
    return img


def generate_icon():
    """Generate assets/novasentinel.ico with multiple resolutions."""
    out = os.path.join(ASSETS_DIR, "novasentinel.ico")
    sizes = [256, 128, 64, 48, 32, 16]
    images = []
    for s in sizes:
        img = build_logo_image(s).convert("RGBA")
        images.append(img)
    images[0].save(out, format="ICO", sizes=[(s, s) for s in sizes],
                   append_images=images[1:])
    print(f"[OK] Icon saved:  {out}")


def generate_png():
    """Generate assets/novasentinel.png at 512×512."""
    out = os.path.join(ASSETS_DIR, "novasentinel.png")
    img = build_logo_image(512).convert("RGBA")
    img.save(out, format="PNG", optimize=True)
    print(f"[OK] PNG saved:   {out}")


def generate_splash():
    """Generate assets/splash.png — 800×400 splash screen."""
    W, H = 800, 400
    out = os.path.join(ASSETS_DIR, "splash.png")

    img = Image.new("RGBA", (W, H), (*BG, 255))
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    # Hex grid bg
    _draw_hex_grid(draw, W, H, spacing=45, alpha=12)

    # Logo on left
    logo_size = 200
    logo_img = build_logo_image(logo_size)
    logo_x, logo_y = 60, (H - logo_size) // 2
    img.paste(logo_img, (logo_x, logo_y), logo_img)

    # Right: Text area
    text_x = logo_x + logo_size + 50

    # Title
    title_font_size = 56
    try:
        font_title = ImageFont.truetype("arial.ttf", title_font_size)
        font_sub   = ImageFont.truetype("arial.ttf", 20)
        font_ver   = ImageFont.truetype("arial.ttf", 14)
    except Exception:
        font_title = ImageFont.load_default()
        font_sub   = font_title
        font_ver   = font_title

    draw.text((text_x, 120), "NovaSentinel", font=font_title, fill=TEXT)
    draw.text((text_x, 190), "AI-Powered Cybersecurity Platform", font=font_sub, fill=ACCENT)
    draw.text((text_x, 220), "v4.1 · Windows Edition", font=font_ver, fill=(140, 110, 110))

    # Loading bar
    bar_y = H - 18
    bar_w = W - 80
    draw.rectangle((40, bar_y, 40 + bar_w, bar_y + 4), fill=(30, 20, 20))
    draw.rectangle((40, bar_y, 40 + int(bar_w * 0.72), bar_y + 4), fill=ACCENT)

    # Status text
    draw.text((40, bar_y - 20), "Initializing security engines...", font=font_ver, fill=(120, 90, 90))

    # Separator line
    sep_x = text_x - 25
    draw.line([(sep_x, 100), (sep_x, 300)], fill=(*ACCENT[:3], 60), width=1)

    img = Image.alpha_composite(img, overlay)
    img.convert("RGB").save(out, format="PNG", optimize=True)
    print("[OK] Splash saved: " + out)


def generate_github_banner():
    """Generate assets/github_banner.png — 1280×640."""
    W, H = 1280, 640
    out = os.path.join(ASSETS_DIR, "github_banner.png")

    img = Image.new("RGBA", (W, H), (*BG, 255))
    overlay = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    # Hex grid
    _draw_hex_grid(draw, W, H, spacing=55, alpha=14)

    # Gradient overlay on right side (darker)
    for x in range(W // 2, W):
        alpha = int(40 * (x - W // 2) / (W // 2))
        draw.line([(x, 0), (x, H)], fill=(0, 0, 0, alpha))

    # Logo left
    logo_size = 280
    logo_img = build_logo_image(logo_size)
    logo_x = 80
    logo_y = (H - logo_size) // 2
    img.paste(logo_img, (logo_x, logo_y), logo_img)

    # Text area right of logo
    text_x = logo_x + logo_size + 60

    try:
        font_big  = ImageFont.truetype("arial.ttf", 80)
        font_med  = ImageFont.truetype("arial.ttf", 26)
        font_sm   = ImageFont.truetype("arial.ttf", 18)
        font_xs   = ImageFont.truetype("arial.ttf", 15)
    except Exception:
        font_big  = ImageFont.load_default()
        font_med  = font_big
        font_sm   = font_big
        font_xs   = font_big

    # Main title
    draw.text((text_x, 150), "NovaSentinel", font=font_big, fill=TEXT)
    # Underline accent
    draw.rectangle((text_x, 240, text_x + 420, 244), fill=ACCENT)
    # Subtitle
    draw.text((text_x, 260), "AI-Powered Cybersecurity Platform", font=font_med, fill=(200, 170, 170))
    draw.text((text_x, 298), "for Windows", font=font_sm, fill=(140, 110, 110))

    # Tech badges
    badges = ["PyQt6", "Python 3.11", "ML-Powered", "Real-Time", "Windows"]
    bx = text_x
    by = 360
    for badge in badges:
        bw = len(badge) * 11 + 24
        draw.rectangle((bx, by, bx + bw, by + 28), fill=(*SURFACE, 220), outline=(*ACCENT[:3], 180), width=1)
        draw.text((bx + 12, by + 6), badge, font=font_xs, fill=ACCENT)
        bx += bw + 10

    # Network graph visualization (right side)
    nodes = [
        (1050, 200), (1150, 160), (1200, 280), (1100, 350),
        (950, 300), (1050, 420), (1170, 450),
    ]
    for i, (nx, ny) in enumerate(nodes):
        for j, (mx, my) in enumerate(nodes):
            if i < j and abs(i - j) < 3:
                alpha = 40 + (i * 10)
                draw.line([(nx, ny), (mx, my)], fill=(*ACCENT[:3], alpha), width=1)
        nr = 8 if i == 0 else 5
        draw.ellipse((nx - nr, ny - nr, nx + nr, ny + nr), fill=ACCENT, outline=TEXT)

    img = Image.alpha_composite(img, overlay)
    img.convert("RGB").save(out, format="PNG", optimize=True)
    print("[OK] Banner saved: " + out)


if __name__ == "__main__":
    print("\n  NovaSentinel Asset Generator")
    print("  ============================\n")
    generate_icon()
    generate_png()
    generate_splash()
    generate_github_banner()
    print(f"\n  All assets written to: {ASSETS_DIR}\n")
