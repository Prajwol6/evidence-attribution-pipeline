#!/usr/bin/env python3
"""Convert architecture_diagram.md to architecture_diagram.png using matplotlib."""
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as patches

MD_PATH  = '/home/prajwol/evidence-attribution-pipeline/architecture_diagram.md'
PNG_PATH = '/home/prajwol/evidence-attribution-pipeline/architecture_diagram.png'

# Catppuccin Mocha colour scheme
BG      = '#1e1e2e'
CODE_BG = '#181825'
C = {
    'text':  '#cdd6f4',
    'h1':    '#cba6f7',
    'h2':    '#89b4fa',
    'code':  '#a6e3a1',
    'sep':   '#45475a',
    'table': '#fab387',
}

BASE_PT  = 7.5    # base monospace font size (points)
MARGIN_L = 0.5    # left margin (inches)
MARGIN_TB = 0.45  # top/bottom margin (inches)
FIG_W    = 14.0   # figure width (inches) — tight bbox trims excess
DPI      = 150

# Per-kind line heights (inches); sized so text at each pt size fits
LH = {
    'h1':    0.27,   # 14 pt → ~29 px @ 150 dpi; 0.27 in = 40.5 px ✓
    'h2':    0.23,   # 11 pt → ~23 px; 0.23 in = 34.5 px ✓
    'code':  0.155,  # 7.5 pt → ~16 px; 0.155 in = 23 px ✓
    'text':  0.155,
    'table': 0.155,
    'sep':   0.13,
    'blank': 0.09,
    'fence': 0.0,    # fence lines are invisible
}


def classify(line: str, in_code: bool) -> str:
    s = line.strip()
    if s.startswith('```'):
        return 'fence'
    if in_code:
        return 'code'
    if not s:
        return 'blank'
    if s == '---':
        return 'sep'
    if line.startswith('# ') and not line.startswith('## '):
        return 'h1'
    if line.startswith('## '):
        return 'h2'
    if s.startswith('|'):
        return 'table'
    return 'text'


def main():
    with open(MD_PATH, encoding='utf-8') as f:
        raw_lines = f.read().split('\n')

    # ── Pass 1: classify every line, compute y positions ──────────────────
    kinds: list[str] = []
    in_code = False
    for line in raw_lines:
        k = classify(line, in_code)
        if k == 'fence':
            in_code = not in_code
        kinds.append(k)

    ys: list[float] = []
    y = MARGIN_TB
    for k in kinds:
        ys.append(y)
        y += LH.get(k, LH['text'])
    fig_h = y + MARGIN_TB

    # ── Set up figure ──────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(FIG_W, fig_h))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.set_xlim(0, FIG_W)
    ax.set_ylim(fig_h, 0)   # y increases downward
    ax.axis('off')

    # ── Pass 2: draw code-block background rectangles (z=0) ───────────────
    in_code = False
    code_start_y = None
    for i, (line, k) in enumerate(zip(raw_lines, kinds)):
        if k != 'fence':
            continue
        if not in_code:
            in_code = True
            code_start_y = ys[i]
        else:
            in_code = False
            block_h = ys[i] - code_start_y  # fence lines have 0 height
            ax.add_patch(patches.Rectangle(
                (MARGIN_L - 0.15, code_start_y),
                FIG_W - MARGIN_L + 0.1,
                block_h,
                facecolor=CODE_BG,
                edgecolor='#313244',
                linewidth=0.5,
                zorder=0,
            ))
            code_start_y = None

    # ── Pass 3: draw text (z=1) ───────────────────────────────────────────
    in_code = False
    for i, (line, k) in enumerate(zip(raw_lines, kinds)):
        y   = ys[i]
        lh  = LH.get(k, LH['text'])

        if k == 'fence':
            in_code = not in_code
            continue

        if k == 'sep':
            mid_y = y + lh * 0.5
            ax.plot([MARGIN_L, FIG_W - 0.3], [mid_y, mid_y],
                    color=C['sep'], linewidth=0.8, zorder=1)
            continue

        if k == 'blank':
            continue

        # Determine text, colour, font properties
        if k == 'h1':
            text, color, fs, fw, ff = line[2:], C['h1'], 14, 'bold', 'sans-serif'
        elif k == 'h2':
            text, color, fs, fw, ff = line[3:], C['h2'], 11, 'bold', 'sans-serif'
        elif k == 'code':
            text, color, fs, fw, ff = line, C['code'], BASE_PT, 'normal', 'monospace'
        elif k == 'table':
            text, color, fs, fw, ff = line, C['table'], BASE_PT, 'normal', 'monospace'
        else:
            text, color, fs, fw, ff = line, C['text'], BASE_PT, 'normal', 'monospace'

        ax.text(
            MARGIN_L, y,
            text,
            color=color, fontsize=fs, fontweight=fw, fontfamily=ff,
            va='top', ha='left', zorder=1, clip_on=True,
        )

    plt.savefig(PNG_PATH, dpi=DPI, bbox_inches='tight',
                facecolor=BG, pad_inches=0.3)
    plt.close(fig)
    print(f'Saved → {PNG_PATH}')


if __name__ == '__main__':
    main()
