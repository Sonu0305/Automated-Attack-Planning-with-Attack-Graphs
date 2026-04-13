"""Unit tests for visualization/dashboard.py."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from visualization.dashboard import _assemble_html


def test_plotly_library_is_injected_before_plot_calls():
    """Dashboard HTML must define Plotly before any Plotly.newPlot call."""
    html = _assemble_html([
        '<div id="panel1"></div><script>Plotly.newPlot("panel1", [], {});</script>',
        '<div id="panel2"></div><script>Plotly.newPlot("panel2", [], {});</script>',
        '<div id="panel3"></div><script>Plotly.newPlot("panel3", [], {});</script>',
        '<div id="panel4"></div><script>Plotly.newPlot("panel4", [], {});</script>',
        '<div id="panel5"></div><script>Plotly.newPlot("panel5", [], {});</script>',
    ])

    head_start = html.find("<head>")
    head_end = html.find("</head>")
    body_start = html.find("<body>")
    plotly_definition = html.find("plotly.js v", head_start, head_end)
    first_plot_call = html.find("Plotly.newPlot", body_start)

    assert plotly_definition != -1
    assert first_plot_call != -1
    assert head_start != -1
    assert head_end != -1
    assert body_start != -1
    assert plotly_definition < head_end < first_plot_call
