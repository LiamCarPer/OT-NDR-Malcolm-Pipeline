#!/usr/bin/env python3
"""
Render the committed asciinema cast to the GIF and MP4 in this directory.

The demo is recorded with asciinema, which stores a real terminal session as a
timing-accurate cast file. Committing the cast means the animation can be
re-rendered or played back (`asciinema play assets/pipeline_demo.cast`) instead
of being an opaque binary nobody can check.

Requires pyte, Pillow and ffmpeg:

    pip install pyte pillow
    python3 assets/render_cast.py

Usage:
    python3 assets/render_cast.py [cast] [out.gif] [out.mp4]
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pyte
from PIL import Image, ImageDraw, ImageFont

ASSETS = Path(__file__).resolve().parent
CAST = Path(sys.argv[1]) if len(sys.argv) > 1 else ASSETS / "pipeline_demo.cast"
OUT_GIF = Path(sys.argv[2]) if len(sys.argv) > 2 else ASSETS / "pipeline_demo.gif"
OUT_MP4 = Path(sys.argv[3]) if len(sys.argv) > 3 else ASSETS / "pipeline_demo.mp4"

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_SIZE = 17
PAD = 12
BG = "#101014"
FG = "#d4d4d8"
MP4_FPS = 12
FINAL_HOLD_SECONDS = 4.0
MAX_HOLD_SECONDS = 3.0

PALETTE = {
    "black": "#1c1c22", "red": "#e05561", "green": "#8cc265", "brown": "#d1a05a",
    "blue": "#4aa5f0", "magenta": "#c162de", "cyan": "#42b3c2", "white": "#d4d4d8",
    "brightblack": "#5c6370", "brightred": "#ff6b7a", "brightgreen": "#a5d97f",
    "brightbrown": "#ffd166", "brightblue": "#6cb6ff", "brightmagenta": "#d98ff0",
    "brightcyan": "#5fd4e6", "brightwhite": "#ffffff", "default": FG,
}


def color_for(name: str) -> str:
    """Map a pyte colour name or hex string to a hex colour."""
    if not name or name == "default":
        return FG
    if name in PALETTE:
        return PALETTE[name]
    return "#" + name if len(name) == 6 else FG


def load_events() -> tuple[dict, list[tuple[float, str]]]:
    """Read an asciinema v2 cast into (header, output events)."""
    lines = CAST.read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    events = []
    for line in lines[1:]:
        if not line.strip():
            continue
        time, kind, data = json.loads(line)
        if kind == "o":
            events.append((time, data))
    return header, events


def render() -> tuple[list[Image.Image], list[int], int, int]:
    """Replay the cast through a terminal emulator and draw one image per change."""
    header, events = load_events()
    cols, rows = header["width"], header["height"]
    screen = pyte.Screen(cols, rows)
    stream = pyte.Stream(screen)

    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    char_w = font.getlength("M")
    line_h = int(FONT_SIZE * 1.32)
    size = (int(char_w * cols) + 2 * PAD, line_h * rows + 2 * PAD)

    frames: list[Image.Image] = []
    durations: list[int] = []
    previous = None
    times = [event[0] for event in events] + [events[-1][0] + FINAL_HOLD_SECONDS]

    for index, (time, data) in enumerate(events):
        stream.feed(data)
        state = tuple(screen.display)
        if state == previous:
            continue
        previous = state

        image = Image.new("RGB", size, BG)
        draw = ImageDraw.Draw(image)
        for row, text in enumerate(state):
            if not text.strip():
                continue
            y = PAD + row * line_h
            x = PAD
            run, run_color = "", FG
            for col, char in enumerate(text):
                cell = screen.buffer[row][col]
                if isinstance(cell, str):
                    data_char, fg = cell or " ", FG
                else:
                    data_char, fg = cell.data or " ", color_for(cell.fg)
                if fg != run_color and run:
                    draw.text((x, y), run, font=font, fill=run_color)
                    x += font.getlength(run)
                    run = ""
                run_color = fg
                run += data_char
            if run:
                draw.text((x, y), run, font=font, fill=run_color)

        frames.append(image)
        hold = min(times[index + 1] - time, MAX_HOLD_SECONDS)
        durations.append(max(int(hold * 100), 6))

    return frames, durations, size[0], size[1]


def main() -> None:
    """Write the GIF and MP4 next to the cast."""
    frames, durations, width, height = render()
    print(f"{len(frames)} frames at {width}x{height}, {sum(durations) / 100:.1f}s")

    frames[0].save(
        OUT_GIF,
        save_all=True,
        append_images=frames[1:],
        duration=durations,
        loop=0,
        optimize=True,
        disposal=2,
    )
    print(f"gif: {OUT_GIF} ({OUT_GIF.stat().st_size // 1024} KB)")

    # MP4 needs a constant frame rate, so each frame is expanded by its duration.
    tmp = Path("/tmp/ot-ndr-mp4frames")
    subprocess.run(["rm", "-rf", str(tmp)], check=True)
    tmp.mkdir(parents=True)
    index = 0
    for image, duration in zip(frames, durations):
        for _ in range(max(1, round(duration / 100 * MP4_FPS))):
            image.save(tmp / f"{index:05d}.png")
            index += 1
    subprocess.run(
        ["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(MP4_FPS),
         "-i", str(tmp / "%05d.png"), "-pix_fmt", "yuv420p", "-crf", "20",
         "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2", str(OUT_MP4)],
        check=True,
    )
    print(f"mp4: {OUT_MP4} ({OUT_MP4.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
