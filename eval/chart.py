"""Hand-written SVG charts for the reliability eval and the red-team runs."""

from __future__ import annotations

from pathlib import Path


def _line(points, color, label):
    pts = " ".join(f"{x},{y}" for x, y in points)
    circles = "".join(
        f'<circle cx="{x}" cy="{y}" r="4" fill="{color}"/>' for x, y in points
    )
    return (
        f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{pts}"/>{circles}'
    )


def write_svg(
    path: Path,
    failure_rates: list[float],
    on_rates: list[float],
    off_rates: list[float],
) -> None:
    W, H = 720, 460
    ml, mr, mt, mb = 70, 30, 50, 60
    pw, ph = W - ml - mr, H - mt - mb

    def x_of(i: int) -> float:
        return ml + (pw * i / max(1, len(failure_rates) - 1))

    def y_of(rate: float) -> float:
        return mt + ph * (1.0 - rate)

    on_pts = [(x_of(i), y_of(r)) for i, r in enumerate(on_rates)]
    off_pts = [(x_of(i), y_of(r)) for i, r in enumerate(off_rates)]

    grid = []
    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = y_of(frac)
        grid.append(f'<line x1="{ml}" y1="{y}" x2="{ml+pw}" y2="{y}" stroke="#e2e8f0"/>')
        grid.append(
            f'<text x="{ml-10}" y="{y+4}" text-anchor="end" font-size="12" '
            f'fill="#475569">{int(frac*100)}%</text>'
        )
    xticks = []
    for i, fr in enumerate(failure_rates):
        x = x_of(i)
        xticks.append(
            f'<text x="{x}" y="{mt+ph+24}" text-anchor="middle" font-size="12" '
            f'fill="#475569">{int(fr*100)}%</text>'
        )

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}"
     viewBox="0 0 {W} {H}" font-family="Segoe UI, sans-serif">
  <rect width="{W}" height="{H}" fill="white"/>
  <text x="{W/2}" y="26" text-anchor="middle" font-size="18" font-weight="700"
        fill="#0f172a">Task success rate vs. injected-failure rate</text>
  {''.join(grid)}
  {''.join(xticks)}
  <text x="{ml+pw/2}" y="{H-12}" text-anchor="middle" font-size="13"
        fill="#0f172a">Injected failure rate</text>
  <text x="18" y="{mt+ph/2}" text-anchor="middle" font-size="13" fill="#0f172a"
        transform="rotate(-90 18 {mt+ph/2})">Task success rate</text>
  {_line(on_pts, '#16a34a', 'Resilience ON')}
  {_line(off_pts, '#dc2626', 'Resilience OFF')}
  <rect x="{ml+20}" y="{mt+10}" width="14" height="14" fill="#16a34a"/>
  <text x="{ml+40}" y="{mt+22}" font-size="13" fill="#0f172a">Resilience ON</text>
  <rect x="{ml+20}" y="{mt+34}" width="14" height="14" fill="#dc2626"/>
  <text x="{ml+40}" y="{mt+46}" font-size="13" fill="#0f172a">Resilience OFF</text>
</svg>
"""
    path.write_text(svg, encoding="utf-8")


def try_write_png(
    path: Path,
    failure_rates: list[float],
    on_rates: list[float],
    off_rates: list[float],
) -> bool:
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:  # noqa: BLE001
        return False

    xs = [int(r * 100) for r in failure_rates]
    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    ax.plot(xs, [r * 100 for r in on_rates], "o-", color="#16a34a", label="Resilience ON")
    ax.plot(xs, [r * 100 for r in off_rates], "o-", color="#dc2626", label="Resilience OFF")
    ax.set_xlabel("Injected failure rate (%)")
    ax.set_ylabel("Task success rate (%)")
    ax.set_title("Task success rate vs. injected-failure rate")
    ax.set_ylim(0, 105)
    ax.grid(True, alpha=0.3)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return True


def write_redteam_svg(path: Path, data: dict) -> None:
    # Attack success rate per attacker goal, one bar per run. Same hand-written
    # SVG approach as write_svg so the chart needs no plotting library.
    runs = list(data["runs"])
    colors = {"http": "#16a34a", "inprocess": "#2563eb", "inprocess-v1": "#7c3aed",
              "ablation": "#dc2626"}
    labels = {"http": "Hardened (MCP/HTTP)", "inprocess": "Hardened (in-process)",
              "inprocess-v1": "Hardened, v1 tenant credential",
              "ablation": "Ablation (boundary layers off)"}
    goals = list(data["corpus"]["by_goal"])
    W, H = 760, 460
    ml, mr, mt, mb = 70, 30, 80, 70
    pw, ph = W - ml - mr, H - mt - mb
    group = pw / max(1, len(goals))
    bar = group * 0.8 / max(1, len(runs))

    def y_of(rate: float) -> float:
        return mt + ph * (1.0 - rate)

    parts = []
    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = y_of(frac)
        parts.append(f'<line x1="{ml}" y1="{y}" x2="{ml+pw}" y2="{y}" stroke="#e2e8f0"/>')
        parts.append(f'<text x="{ml-10}" y="{y+4}" text-anchor="end" font-size="12" '
                     f'fill="#475569">{int(frac*100)}%</text>')
    for gi, goal in enumerate(goals):
        x0 = ml + gi * group + group * 0.1
        for ri, run in enumerate(runs):
            g = data["runs"][run]["summary"]["by_goal"][goal]
            rate = g["attack_successes"] / g["cases"] if g["cases"] else 0.0
            x = x0 + ri * bar
            y = y_of(rate)
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar-2:.1f}" '
                         f'height="{mt+ph-y:.1f}" fill="{colors.get(run, "#64748b")}"/>')
            parts.append(f'<text x="{x+bar/2-1:.1f}" y="{y-4:.1f}" text-anchor="middle" '
                         f'font-size="10" fill="#0f172a">{g["attack_successes"]}/{g["cases"]}'
                         f'</text>')
        parts.append(f'<text x="{ml+gi*group+group/2:.1f}" y="{mt+ph+20}" '
                     f'text-anchor="middle" font-size="11" fill="#475569">'
                     f'{goal.replace("_", " ")}</text>')
    for ri, run in enumerate(runs):
        y = 42 + ri * 0
        x = ml + ri * 230
        parts.append(f'<rect x="{x}" y="{y}" width="14" height="14" '
                     f'fill="{colors.get(run, "#64748b")}"/>')
        parts.append(f'<text x="{x+20}" y="{y+12}" font-size="12" fill="#0f172a">'
                     f'{labels.get(run, run)}</text>')

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}"
     viewBox="0 0 {W} {H}" font-family="Segoe UI, sans-serif">
  <rect width="{W}" height="{H}" fill="white"/>
  <text x="{W/2}" y="26" text-anchor="middle" font-size="18" font-weight="700"
        fill="#0f172a">Prompt-injection attack success by goal</text>
  {''.join(parts)}
  <text x="18" y="{mt+ph/2}" text-anchor="middle" font-size="13" fill="#0f172a"
        transform="rotate(-90 18 {mt+ph/2})">Attack success rate</text>
  <text x="{ml+pw/2}" y="{H-14}" text-anchor="middle" font-size="13"
        fill="#0f172a">Attacker goal ({data['corpus']['cases']} cases)</text>
</svg>
"""
    path.write_text(svg, encoding="utf-8")
