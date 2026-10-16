"""Create smooth animated demo GIF from authentic UI screenshots."""

import os
from pathlib import Path
from PIL import Image

IMAGES_DIR = Path("docs/images")
FRAME_PATHS = [
    IMAGES_DIR / "proctrace_waterfall.png",
    IMAGES_DIR / "proctrace_inspector.png",
    IMAGES_DIR / "proctrace_triage.png",
    IMAGES_DIR / "proctrace_errors.png",
    IMAGES_DIR / "proctrace_waterfall.png",
]

def make_gif():
    images = []
    # Target size for crisp GitHub README preview (e.g. 1080px wide)
    target_width = 1080

    for path in FRAME_PATHS:
        if not path.exists():
            print(f"Warning: {path} does not exist.")
            continue
        im = Image.open(path).convert("RGB")
        aspect = im.height / im.width
        target_height = int(target_width * aspect)
        resized = im.resize((target_width, target_height), Image.Resampling.LANCZOS)
        images.append(resized)

    if not images:
        print("No images found.")
        return

    # Create sequence with durations (in ms):
    # Waterfall: 2500ms, Inspector: 2500ms, Triage: 2500ms, Errors: 2500ms
    durations = [2500, 2500, 2500, 2500, 1500]

    out_gif = IMAGES_DIR / "proctrace_demo.gif"
    images[0].save(
        out_gif,
        save_all=True,
        append_images=images[1:],
        duration=durations[:len(images)],
        loop=0,
        optimize=True,
    )
    print(f"Created animated demo GIF at {out_gif}, size: {os.path.getsize(out_gif):,} bytes")

if __name__ == "__main__":
    make_gif()
