# Viadere brand assets

The identity in one place is `brand-guide.html`, a self-contained page you open in a browser. It covers the mark, its meaning, lockups, app icons, palette, clear space, minimum sizes, do's and don'ts, typography and component principles.

Every vector here comes from **one Bézier source** (`tools/geom.js` + `tools/final.json`). The SVGs, PDFs, PNGs, the asset catalog and the Swift path data are all generated from it, so they cannot drift apart.

## Files

| Path | What |
|---|---|
| `svg/viadere-mark.svg` | Primary mark: charcoal → ivory → champagne, for ivory or white backgrounds |
| `svg/viadere-mark-on-dark.svg` | Mark tuned for black or charcoal backgrounds |
| `svg/viadere-mark-mono-dark.svg` / `-mono-light.svg` | Single colour (charcoal / ivory). The twist is kept by drawing the back faces at 62% opacity |
| `svg/viadere-wordmark(-on-dark).svg` | Outlined `viadere` wordmark (no font dependency) |
| `svg/viadere-lockup-horizontal(-on-dark).svg` | Mark + wordmark, with built-in clear space of one dot diameter |
| `svg/viadere-lockup-stacked(-on-dark).svg` | Stacked lockup, with built-in clear space |
| `svg/app-icon-light.svg` / `-dark.svg` / `-tinted.svg` | Full-bleed 1024 × 1024 icon artwork (iOS applies the mask) |
| `png/*` | 1024-px renders (icons are opaque RGB; marks and lockups are transparent) |
| `pdf/*` | Vector PDFs (the asset catalog uses these) |
| `../App/Shared/DesignSystem/ViadereMark.swift` | SwiftUI mark, wordmark, lockup and `ViadereBrand` palette (SwiftUI only, generated). **Moved:** `App/Shared/DesignSystem` is now the source of truth |
| `../App/Shared/DesignSystem/ViadereDesignSystem.swift` | Custom components and tokens (buttons, field, card, row, toggle, segmented, badge, section header, slide-to-approve / approve–deny, empty state). **Moved** with the mark; `ViadereComponents.swift` beside it adds the app-level components (tab bar, chips, code and OTP fields, countdown ring, notices) |
| `tools/` | Generators (Node + Playwright/Chromium, Python + fontTools/Pillow). Paths inside assume the original scratch layout, so adjust them before re-running |
| `../App/Resources/Assets.xcassets` | `AppIcon` (light, dark and tinted appearances), `BrandMark` (light/dark), `BrandMarkMonoDark`, `BrandMarkMonoLight`, `BrandMarkTemplate` (template rendering), `Wordmark`, `LockupHorizontal`, and `Colors/*` colour sets |
| `../App/Resources/Fonts` | Outfit Light / Regular / SemiBold TTF + `OFL.txt` |

## Palette

| Name | Hex | Role |
|---|---|---|
| Charcoal | `#1F1E1C` | Primary dark, text, primary button (light mode) |
| Graphite | `#4A4844` | Secondary dark |
| Silver | `#C9C4BB` | Neutral mid-tone |
| Ivory | `#F5F2EC` | Primary light, backgrounds |
| Champagne | `#C2AE8E` | Accent (dark-mode accent `#CDB993`; accent text on ivory `#8C7550`) |

Semantic colour sets (light / dark):

| Token | Light | Dark |
|---|---|---|
| Background | `#F5F2EC` | `#121211` |
| Surface | `#FCFBF8` | `#1C1B1A` |
| SurfaceRaised | `#FFFFFF` | `#262523` |
| TextPrimary | `#1F1E1C` | `#F3F0EA` |
| TextSecondary | `#6B675F` | `#A29D94` |
| TextTertiary | `#9A958C` | `#6F6B64` |
| Accent | `#8C7550` | `#CDB993` |
| OnAccent | `#FFFFFF` | `#1F1E1C` |
| Danger | `#A3412E` | `#E08068` |
| Success | `#4C7458` | `#8DBB98` |
| Hairline | Charcoal at 10% | `#F3F0EA` at 12% |

## Geometry

- The ribbon is a constant-width band that follows a zig-zag centreline. Its outer corners are rounded, its inner notches are sharp and both ends taper to a point. The three front faces (**v**, **i**-arch, **a**-arch) are separated from the back faces by "twist" curves: the ribbon's inner contour as it wraps each crest and trough.
- View box: **321.7 × 146** (ribbon 321.7 × 100, plus the dot). The ribbon proportion is **3.2 : 1**, measured from the reference artwork, where the ribbon spans ~3.25 : 1. The "2.6×" label in the reference proportions sheet does not match its own drawing, so the drawn artwork was followed. With the dot included, the mark is 2.2 : 1.
- Dot: diameter = 0.41 × ribbon height, centred above the "i" rise, floating 0.05 × ribbon height above the ribbon.
- Clear space: one dot diameter (**d**) on every side. Minimum size: gradient mark 32 px wide; monochrome down to 20 px; horizontal lockup 96 px.

## Typography

- **Wordmark:** [Outfit](https://github.com/Outfitio/Outfit-Fonts) by The Outfit Project Authors, **SIL Open Font License 1.1**. Sourced from the `@fontsource/outfit@5.3.0` npm package (latin subset) and outlined with fontTools: "via" is SemiBold (600), "dere" is Light (300), with tracking of −0.008 em. The OFL allows bundling, so the TTFs and `OFL.txt` are in `App/Resources/Fonts`. To use them in SwiftUI, list them under `UIAppFonts` in Info.plist (`Outfit-Light.ttf`, `Outfit-Regular.ttf`, `Outfit-SemiBold.ttf`).
- **Interface:** SF Pro (system) with Dynamic Type. See `ViadereType`.

## Using it in the app

```swift
ViadereMark()                                  // adapts to light/dark
ViadereMark(style: .primary).frame(height: 64) // fixed style; keeps its aspect ratio
ViadereMark.monochrome(.white)                 // single colour
ViadereWordmark(size: 28)                      // Outfit (falls back to the system font if not registered)
ViadereWordmark(size: 28, typeface: .sfRounded)
ViadereLockup(.horizontal, ribbonHeight: 32)
    .padding(ViadereLockup.clearSpace(ribbonHeight: 32))
Image("BrandMark").resizable().scaledToFit()   // asset-catalog vector alternative
Button("Continue") { }.buttonStyle(.viadere(.primary))
Toggle("Face ID", isOn: $on).toggleStyle(.viadere)
ViadereSlideToConfirm { approve() }
```

`ViadereDesignSystem.swift` depends on `ViadereMark.swift`. Both target iOS 17+.

## Notes

- The AppIcon set uses the single-size 1024 format (Xcode 15+). The `dark` and `tinted` appearances are honoured on iOS 18 / Xcode 16; older toolchains use the light icon.
- This is a high-fidelity vector interpretation of the reference images, not the original designer's source files. If a designer delivers final masters, replace `tools/final.json` (or the SVG/PDF files directly) and regenerate.

> **Source of truth moved.** The SwiftUI files that used to live in `Design/swift/` are now part of the app target at `App/Shared/DesignSystem/` and are compiled into every UI target (app, App Clip, notification content, widgets, watch). Edit them there. The generators under `tools/` still emit the geometry; copy regenerated `ViadereMark.swift` output into `App/Shared/DesignSystem/`.
