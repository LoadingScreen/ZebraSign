# Generates the zebra-stripe images used by the pages:
#   pages/hide.png     faint hide pattern behind the header (white on transparent,
#                      used as a CSS mask so it takes the page's text colour)
#   pages/favicon.png  browser-tab icon (black stripes on a white rounded square)
# Stripes come from a warped stripe field: stripe where sin(2*pi*phase) > t(x,y).
# The warp keeps stripes roughly parallel, phase noise makes them fork, and a
# varying threshold thins some until they end in points.
# Usage: python3 tools/stripes.py   (needs numpy and Pillow)
import io, os
import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
PAGES = os.path.join(HERE, '..', 'pages')

def waves(rng, x, y, n, scale, fmin, fmax):
    out = np.zeros_like(x)
    for _ in range(n):
        fx, fy = rng.uniform(fmin, fmax) / scale, rng.uniform(fmin, fmax) / scale
        out += np.sin(fx * x + fy * y + rng.uniform(0, 6.28))
    return out / n

def field(w, h, period, seed, warp_amp, warp_scale, slant, t_amp, t_bias, fork, ss=3):
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:h * ss, 0:w * ss].astype(np.float64) / ss
    warp = warp_amp * (waves(rng, x, y, 5, warp_scale, 0.2, 2.0) + 0.36 * waves(rng, x, y, 3, warp_scale, 1.5, 4.0))
    phase = (x + slant * y + warp) / period + fork * 6 * waves(rng, x, y, 3, warp_scale, 0.3, 1.0)
    t = t_bias + t_amp * waves(rng, x, y, 3, warp_scale * 0.8, 0.8, 2.2)
    on = (np.sin(2 * np.pi * phase) > t).astype(np.float32)
    return on.reshape(h, ss, w, ss).mean(axis=(1, 3))

def save(rgba, name):
    buf = io.BytesIO()
    Image.fromarray(rgba, 'RGBA').save(buf, 'PNG', optimize=True)
    open(os.path.join(PAGES, name), 'wb').write(buf.getvalue())
    print(name, len(buf.getvalue()), 'bytes')

def hide(w=640, h=320, levels=12):
    a = field(w, h, period=21, seed=9, warp_amp=41, warp_scale=71, slant=0.3, t_amp=0.75, t_bias=0.05, fork=0.45)
    yy, xx = np.mgrid[0:h, 0:w].astype(float)
    fade = (np.clip((xx / w - 0.05) / 0.6, 0, 1) ** 1.4      # in from the left
            * np.clip((1 - yy / h) / 0.5, 0, 1)                # out toward the bottom
            * np.clip((1 - xx / w) / 0.12, 0, 1)               # soft right edge
            * np.clip(yy / h / 0.08, 0, 1))                    # soft top edge
    alpha = np.round(a * fade * (levels - 1)) / (levels - 1)  # few levels: compresses well, invisible at low opacity
    rgba = np.zeros((h, w, 4), np.uint8); rgba[..., :3] = 255; rgba[..., 3] = (alpha * 255).astype(np.uint8)
    save(rgba, 'hide.png')

def favicon(n=64):
    a = field(n, n, period=12, seed=21, warp_amp=12, warp_scale=24, slant=0.3, t_amp=0.5, t_bias=0.0, fork=0.35, ss=4)
    yy, xx = np.mgrid[0:n, 0:n] + 0.5
    r = 14; cx = np.clip(xx, r, n - r); cy = np.clip(yy, r, n - r)
    inside = np.clip(r + 0.5 - np.hypot(xx - cx, yy - cy), 0, 1)
    v = (255 * (1 - a)).astype(np.uint8)
    rgba = np.zeros((n, n, 4), np.uint8); rgba[..., 0] = rgba[..., 1] = rgba[..., 2] = v
    rgba[..., 3] = (inside * 255).astype(np.uint8)
    save(rgba, 'favicon.png')

if __name__ == '__main__':
    hide(); favicon()
