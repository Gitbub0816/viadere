import json, os, shutil
from PIL import Image
from fontTools.ttLib import TTFont
R = '/home/user/viadere'
X = f'{R}/App/Resources/Assets.xcassets'
INFO = {"author": "xcode", "version": 1}
def wj(p, d):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w') as f: json.dump(d, f, indent=2); f.write('\n')
wj(f'{X}/Contents.json', {"info": INFO})

# ---- App icon (iOS 17+/Xcode 15+ single size; dark + tinted appearances need Xcode 16 / iOS 18) ----
ai = f'{X}/AppIcon.appiconset'; os.makedirs(ai, exist_ok=True)
for kind in ['light', 'dark', 'tinted']:
    im = Image.open(f'{R}/Design/png/app-icon-{kind}-1024.png').convert('RGB')   # App Store icon: no alpha
    assert im.size == (1024, 1024)
    name = {'light': 'AppIcon-1024.png', 'dark': 'AppIcon-1024-dark.png', 'tinted': 'AppIcon-1024-tinted.png'}[kind]
    im.save(f'{ai}/{name}', optimize=True)
wj(f'{ai}/Contents.json', {"images": [
    {"filename": "AppIcon-1024.png", "idiom": "universal", "platform": "ios", "size": "1024x1024"},
    {"appearances": [{"appearance": "luminosity", "value": "dark"}], "filename": "AppIcon-1024-dark.png", "idiom": "universal", "platform": "ios", "size": "1024x1024"},
    {"appearances": [{"appearance": "luminosity", "value": "tinted"}], "filename": "AppIcon-1024-tinted.png", "idiom": "universal", "platform": "ios", "size": "1024x1024"},
], "info": INFO})

# ---- Vector image sets (PDF, preserves vector representation) ----
def imageset(name, light, dark=None, template=False):
    d = f'{X}/{name}.imageset'
    if os.path.isdir(d): shutil.rmtree(d)
    os.makedirs(d)
    imgs = []
    shutil.copy(f'{R}/Design/pdf/{light}.pdf', f'{d}/{light}.pdf')
    imgs.append({"filename": f"{light}.pdf", "idiom": "universal"})
    if dark:
        shutil.copy(f'{R}/Design/pdf/{dark}.pdf', f'{d}/{dark}.pdf')
        imgs.append({"appearances": [{"appearance": "luminosity", "value": "dark"}], "filename": f"{dark}.pdf", "idiom": "universal"})
    props = {"preserves-vector-representation": True}
    if template: props["template-rendering-intent"] = "template"
    wj(f'{d}/Contents.json', {"images": imgs, "info": INFO, "properties": props})
imageset('BrandMark', 'viadere-mark', 'viadere-mark-on-dark')                 # adapts to light/dark
imageset('BrandMarkMonoDark', 'viadere-mark-mono-dark')                        # charcoal, fixed
imageset('BrandMarkMonoLight', 'viadere-mark-mono-light')                      # ivory, fixed
imageset('BrandMarkTemplate', 'viadere-mark-mono-dark', template=True)         # tint with .foregroundStyle
imageset('Wordmark', 'viadere-wordmark', 'viadere-wordmark-on-dark')
imageset('LockupHorizontal', 'viadere-lockup-horizontal', 'viadere-lockup-horizontal-on-dark')

# ---- Colour sets ----
def comp(hexs, a=1.0):
    h = hexs.lstrip('#')
    return {"color-space": "srgb", "components": {"red": f"0x{h[0:2]}", "green": f"0x{h[2:4]}", "blue": f"0x{h[4:6]}", "alpha": f"{a:.3f}"}}
COLORS = json.load(open('/tmp/claude-0/-home-user-viadere/3b41d0e0-5b55-55a1-acf8-7590519ad1f4/scratchpad/gen/colors.json'))
os.makedirs(f'{X}/Colors', exist_ok=True)
wj(f'{X}/Colors/Contents.json', {"info": INFO, "properties": {"provides-namespace": False}})
for name, spec in COLORS.items():
    lh, la = spec['light'] if isinstance(spec['light'], list) else (spec['light'], 1.0)
    dh, da = spec['dark'] if isinstance(spec['dark'], list) else (spec['dark'], 1.0)
    wj(f'{X}/Colors/{name}.colorset/Contents.json', {"colors": [
        {"color": comp(lh, la), "idiom": "universal"},
        {"appearances": [{"appearance": "luminosity", "value": "dark"}], "color": comp(dh, da), "idiom": "universal"},
    ], "info": INFO})

# ---- Fonts: Outfit (SIL OFL 1.1) converted from the Fontsource woff files to TTF ----
F = f'{R}/App/Resources/Fonts'; os.makedirs(F, exist_ok=True)
src = '/tmp/claude-0/-home-user-viadere/3b41d0e0-5b55-55a1-acf8-7590519ad1f4/scratchpad/fontdl/package'
for w, n in [(300, 'Light'), (400, 'Regular'), (600, 'SemiBold')]:
    f = TTFont(f'{src}/files/outfit-latin-{w}-normal.woff'); f.flavor = None; f.save(f'{F}/Outfit-{n}.ttf')
shutil.copy(f'{src}/LICENSE', f'{F}/OFL.txt')
print('ok')
