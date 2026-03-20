"""
Graph generation module for ChartVault.
Implements secure data visualization with comprehensive error handling.
"""

import plotly.graph_objects as go
import json
import logging
from typing import Dict, Any, Optional, List, Tuple

from config import COLORS, GRAPH_FIGURE_HEIGHT, GRAPH_FIGURE_WIDTH

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Professional color palette
PALETTE = [
    COLORS["secondary"],    # Blue
    COLORS["success"],      # Green
    COLORS["warning"],      # Amber
    COLORS["danger"],       # Red
    "#8B5CF6",             # Purple
    "#06B6D4",             # Cyan
    "#EC4899",             # Pink
    "#F97316",             # Orange
]


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_figure_config() -> dict:
    """Get Plotly figure configuration for consistent styling."""
    return {
        "responsive": True,
        "displayModeBar": True,
        "displaylogo": False,
        "modeBarButtonsToRemove": ["lasso2d", "select2d"],
    }


def get_template() -> dict:
    """Get professional template configuration."""
    return {
        "layout": {
            "font": {"family": "Arial, sans-serif", "size": 11, "color": COLORS["text_primary"]},
            "paper_bgcolor": "white",
            "plot_bgcolor": "#F9FAFB",
            "margin": {"l": 60, "r": 40, "t": 80, "b": 60},
        }
    }


# ============================================================================
# GRAPH CREATION FUNCTIONS
# ============================================================================

def create_line_graph(x_values: List[float], y_values: List[float], 
                      title: str, x_label: str, y_label: str) -> Tuple[bool, Optional[go.Figure], str]:
    """
    Create a professional line graph with error handling.
    
    Args:
        x_values: X-axis values
        y_values: Y-axis values
        title: Graph title
        x_label: X-axis label
        y_label: Y-axis label
        
    Returns:
        Tuple of (success, figure, error_message)
    """
    try:
        # Validate inputs
        if not x_values or not y_values:
            return False, None, "X and Y values cannot be empty"
        
        if len(x_values) != len(y_values):
            return False, None, f"X and Y values must have same length ({len(x_values)} vs {len(y_values)})"
        
        if len(x_values) < 2:
            return False, None, "At least 2 data points required"
        
        # Create figure
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=x_values,
            y=y_values,
            mode='lines+markers',
            name='Data',
            line=dict(
                color=COLORS["secondary"],
                width=3,
                shape='linear'
            ),
            marker=dict(
                size=7,
                color=COLORS["secondary"],
                line=dict(color="white", width=2)
            ),
            hovertemplate='<b>%{x}</b><br>%{y:.2f}<extra></extra>'
        ))
        
        # Update layout with professional styling
        fig.update_layout(
            title={
                "text": title,
                "x": 0.5,
                "xanchor": "center",
                "font": {"size": 18, "color": COLORS["text_primary"], "family": "Arial, sans-serif"}
            },
            xaxis_title=x_label,
            yaxis_title=y_label,
            hovermode='x unified',
            template='plotly_white',
            height=GRAPH_FIGURE_HEIGHT,
            width=GRAPH_FIGURE_WIDTH,
            font=dict(color=COLORS["text_primary"], family="Arial, sans-serif"),
            xaxis=dict(gridcolor="lightgray", showline=True, linewidth=1, linecolor="gray"),
            yaxis=dict(gridcolor="lightgray", showline=True, linewidth=1, linecolor="gray"),
            margin=dict(l=70, r=50, t=100, b=70)
        )
        
        return True, fig, ""
    except Exception as e:
        error_msg = f"Line graph creation error: {str(e)[:100]}"
        logger.error(error_msg)
        return False, None, error_msg


def create_scatter_plot(x_values: List[float], y_values: List[float],
                       title: str, x_label: str, y_label: str) -> Tuple[bool, Optional[go.Figure], str]:
    """
    Create a professional scatter plot with error handling.
    
    Args:
        x_values: X-axis values
        y_values: Y-axis values
        title: Graph title
        x_label: X-axis label
        y_label: Y-axis label
        
    Returns:
        Tuple of (success, figure, error_message)
    """
    try:
        # Validate inputs
        if not x_values or not y_values:
            return False, None, "X and Y values cannot be empty"
        
        if len(x_values) != len(y_values):
            return False, None, f"X and Y values must have same length ({len(x_values)} vs {len(y_values)})"
        
        if len(x_values) < 2:
            return False, None, "At least 2 data points required"
        
        # Create figure
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=x_values,
            y=y_values,
            mode='markers',
            name='Data Points',
            marker=dict(
                size=10,
                color=COLORS["info"],
                opacity=0.7,
                line=dict(width=2, color=COLORS["secondary"]),
                symbol='circle'
            ),
            hovertemplate='<b>X:</b> %{x:.2f}<br><b>Y:</b> %{y:.2f}<extra></extra>'
        ))
        
        # Update layout with professional styling
        fig.update_layout(
            title={
                "text": title,
                "x": 0.5,
                "xanchor": "center",
                "font": {"size": 18, "color": COLORS["text_primary"], "family": "Arial, sans-serif"}
            },
            xaxis_title=x_label,
            yaxis_title=y_label,
            hovermode='closest',
            template='plotly_white',
            height=GRAPH_FIGURE_HEIGHT,
            width=GRAPH_FIGURE_WIDTH,
            font=dict(color=COLORS["text_primary"], family="Arial, sans-serif"),
            xaxis=dict(gridcolor="lightgray", showline=True, linewidth=1, linecolor="gray"),
            yaxis=dict(gridcolor="lightgray", showline=True, linewidth=1, linecolor="gray"),
            margin=dict(l=70, r=50, t=100, b=70)
        )
        
        return True, fig, ""
    except Exception as e:
        error_msg = f"Scatter plot creation error: {str(e)[:100]}"
        logger.error(error_msg)
        return False, None, error_msg


def create_histogram(data: List[float], title: str, x_label: str, y_label: str,
                    bins: int = 30) -> Tuple[bool, Optional[go.Figure], str]:
    """
    Create a professional histogram with error handling.
    
    Args:
        data: Data values
        title: Graph title
        x_label: X-axis label
        y_label: Y-axis label
        bins: Number of bins (2-100)
        
    Returns:
        Tuple of (success, figure, error_message)
    """
    try:
        # Validate inputs
        if not data or len(data) == 0:
            return False, None, "Data cannot be empty"
        
        if len(data) < 2:
            return False, None, "At least 2 data points required"
        
        # Validate bin count
        bins = max(2, min(100, bins))
        
        # Create figure
        fig = go.Figure()
        fig.add_trace(go.Histogram(
            x=data,
            nbinsx=bins,
            name='Frequency',
            marker=dict(
                color=COLORS["warning"],
                line=dict(color=COLORS["secondary"], width=1)
            ),
            hovertemplate='<b>Range:</b> %{x}<br><b>Frequency:</b> %{y}<extra></extra>'
        ))
        
        # Update layout with professional styling
        fig.update_layout(
            title={
                "text": title,
                "x": 0.5,
                "xanchor": "center",
                "font": {"size": 18, "color": COLORS["text_primary"], "family": "Arial, sans-serif"}
            },
            xaxis_title=x_label,
            yaxis_title=y_label,
            showlegend=False,
            template='plotly_white',
            height=GRAPH_FIGURE_HEIGHT,
            width=GRAPH_FIGURE_WIDTH,
            font=dict(color=COLORS["text_primary"], family="Arial, sans-serif"),
            xaxis=dict(gridcolor="lightgray", showline=True, linewidth=1, linecolor="gray"),
            yaxis=dict(gridcolor="lightgray", showline=True, linewidth=1, linecolor="gray"),
            margin=dict(l=70, r=50, t=100, b=70),
            bargap=0.1
        )
        
        return True, fig, ""
    except Exception as e:
        error_msg = f"Histogram creation error: {str(e)[:100]}"
        logger.error(error_msg)
        return False, None, error_msg


def create_pie_chart(labels: List[str], values: List[float],
                    title: str) -> Tuple[bool, Optional[go.Figure], str]:
    """
    Create a professional pie chart with error handling.
    
    Args:
        labels: Label for each slice
        values: Value for each slice
        title: Graph title
        
    Returns:
        Tuple of (success, figure, error_message)
    """
    try:
        # Validate inputs
        if not labels or not values:
            return False, None, "Labels and values cannot be empty"
        
        if len(labels) != len(values):
            return False, None, f"Labels and values must have same length ({len(labels)} vs {len(values)})"
        
        if len(labels) < 2:
            return False, None, "At least 2 categories required"
        
        if any(v <= 0 for v in values):
            return False, None, "All values must be positive"
        
        # Create figure
        fig = go.Figure()
        fig.add_trace(go.Pie(
            labels=labels,
            values=values,
            hoverinfo='label+percent+value',
            textinfo='label+percent',
            textposition='inside',
            marker=dict(
                colors=PALETTE[:len(labels)],
                line=dict(color="white", width=2)
            ),
            hovertemplate='<b>%{label}</b><br>Value: %{value}<br>Percentage: %{percent}<extra></extra>'
        ))
        
        # Update layout with professional styling
        fig.update_layout(
            title={
                "text": title,
                "x": 0.5,
                "xanchor": "center",
                "font": {"size": 18, "color": COLORS["text_primary"], "family": "Arial, sans-serif"}
            },
            template='plotly_white',
            height=GRAPH_FIGURE_HEIGHT,
            width=GRAPH_FIGURE_WIDTH,
            font=dict(color=COLORS["text_primary"], family="Arial, sans-serif"),
            showlegend=True,
            legend=dict(orientation="v", yanchor="middle", y=0.5, xanchor="left", x=1.05),
            margin=dict(l=50, r=200, t=100, b=50)
        )
        
        return True, fig, ""
    except Exception as e:
        error_msg = f"Pie chart creation error: {str(e)[:100]}"
        logger.error(error_msg)
        return False, None, error_msg


def create_box_whisker_plot(data_groups: Dict[str, List[float]], title: str,
                           y_label: str) -> Tuple[bool, Optional[go.Figure], str]:
    """
    Create a professional box-and-whisker plot with error handling.
    
    Args:
        data_groups: Dictionary of {group_name: [values]}
        title: Graph title
        y_label: Y-axis label
        
    Returns:
        Tuple of (success, figure, error_message)
    """
    try:
        # Validate inputs
        if not data_groups:
            return False, None, "No data groups provided"
        
        if any(len(values) == 0 for values in data_groups.values()):
            return False, None, "Data groups cannot be empty"
        
        # Create figure
        fig = go.Figure()
        
        for i, (group_name, values) in enumerate(data_groups.items()):
            fig.add_trace(go.Box(
                y=values,
                name=group_name,
                boxmean='sd',
                marker=dict(
                    size=4,
                    color=PALETTE[i % len(PALETTE)]
                ),
                line=dict(color=PALETTE[i % len(PALETTE)]),
                hovertemplate='<b>%{fullData.name}</b><br>Value: %{y:.2f}<extra></extra>'
            ))
        
        # Update layout with professional styling
        fig.update_layout(
            title={
                "text": title,
                "x": 0.5,
                "xanchor": "center",
                "font": {"size": 18, "color": COLORS["text_primary"], "family": "Arial, sans-serif"}
            },
            yaxis_title=y_label,
            xaxis_title='Groups',
            template='plotly_white',
            height=GRAPH_FIGURE_HEIGHT,
            width=GRAPH_FIGURE_WIDTH,
            font=dict(color=COLORS["text_primary"], family="Arial, sans-serif"),
            showlegend=True,
            hovermode='closest',
            xaxis=dict(gridcolor="lightgray", showline=True, linewidth=1, linecolor="gray"),
            yaxis=dict(gridcolor="lightgray", showline=True, linewidth=1, linecolor="gray"),
            margin=dict(l=70, r=50, t=100, b=70)
        )
        
        return True, fig, ""
    except Exception as e:
        error_msg = f"Box-whisker plot creation error: {str(e)[:100]}"
        logger.error(error_msg)
        return False, None, error_msg


# ============================================================================
# SERIALIZATION FUNCTIONS
# ============================================================================

def serialize_graph(fig: go.Figure) -> Tuple[bool, Optional[str]]:
    """
    Serialize Plotly figure to JSON for storage (encrypted in database).
    
    Args:
        fig: Plotly Figure object
        
    Returns:
        Tuple of (success, json_string)
    """
    try:
        if not isinstance(fig, go.Figure):
            logger.error("Input must be a Plotly Figure")
            return False, None
        
        return True, fig.to_json()
    except Exception as e:
        logger.error(f"Graph serialization error: {e}")
        return False, None


def deserialize_graph(json_str: str) -> Tuple[bool, Optional[go.Figure]]:
    """
    Deserialize Plotly figure from JSON.
    
    Args:
        json_str: JSON string containing figure data
        
    Returns:
        Tuple of (success, Figure object)
    """
    try:
        if not json_str or not isinstance(json_str, str):
            logger.error("JSON string is empty or invalid")
            return False, None
        
        fig_dict = json.loads(json_str)
        fig = go.Figure(fig_dict)
        return True, fig
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {e}")
        return False, None
    except Exception as e:
        logger.error(f"Graph deserialization error: {e}")
        return False, None


__all__ = [
    'create_line_graph', 'create_scatter_plot', 'create_histogram',
    'create_pie_chart', 'create_box_whisker_plot', 'serialize_graph',
    'deserialize_graph', 'get_figure_config', 'get_template',
    'PALETTE'
]
