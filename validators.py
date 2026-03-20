"""
Input validation module for ChartVault.
Prevents injection attacks and ensures data integrity (OWASP A03).
"""

import re
from typing import Tuple, List, Any, Dict, Union
import logging
import math

from config import (
    CHART_TITLE_MAX_LENGTH, AXIS_LABEL_MAX_LENGTH, GRAPH_NAME_MAX_LENGTH,
    MAX_CHART_POINTS, MAX_PIE_SLICES, MIN_CHART_POINTS, HISTOGRAM_MAX_BINS,
    HISTOGRAM_MIN_BINS, PROPORTION_TOLERANCE, MAX_FILE_SIZE_MB,
    DESCRIPTION_MAX_LENGTH
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# BASIC VALIDATION FUNCTIONS
# ============================================================================

def validate_string(value: Any, max_length: int = 255, pattern: str = None) -> Tuple[bool, str]:
    """
    Validate string input with optional pattern matching.
    
    Args:
        value: Value to validate
        max_length: Maximum allowed length
        pattern: Optional regex pattern to match
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(value, str):
        return False, "Input must be a string"
    
    if len(value) == 0:
        return False, "Input cannot be empty"
    
    if len(value) > max_length:
        return False, f"Input exceeds maximum length of {max_length} characters"
    
    if pattern and not re.match(pattern, value):
        return False, "Input format is invalid"
    
    return True, ""


def validate_number(value: Any, min_value: float = None, max_value: float = None) -> Tuple[bool, str, float]:
    """
    Validate a single number within range.
    
    Args:
        value: Number to validate
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        Tuple of (is_valid, error_message, parsed_number)
    """
    try:
        num = float(value)
        
        # Check for NaN or infinity
        if math.isnan(num) or math.isinf(num):
            return False, "Number is invalid (NaN or infinity)", 0.0
        
        # Check range
        if min_value is not None and num < min_value:
            return False, f"Value must be at least {min_value}", 0.0
        
        if max_value is not None and num > max_value:
            return False, f"Value must not exceed {max_value}", 0.0
        
        return True, "", num
    except (ValueError, TypeError):
        return False, "Value must be a valid number", 0.0


def validate_integer(value: Any, min_value: int = None, max_value: int = None) -> Tuple[bool, str, int]:
    """
    Validate integer input within range.
    
    Args:
        value: Integer to validate
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        Tuple of (is_valid, error_message, parsed_integer)
    """
    try:
        num = int(float(value))
        
        if min_value is not None and num < min_value:
            return False, f"Value must be at least {min_value}", 0
        
        if max_value is not None and num > max_value:
            return False, f"Value must not exceed {max_value}", 0
        
        return True, "", num
    except (ValueError, TypeError):
        return False, "Value must be a valid integer", 0


# ============================================================================
# CHART PARAMETER VALIDATION
# ============================================================================

def validate_chart_title(title: str) -> Tuple[bool, str]:
    """
    Validate chart title with XSS protection.
    
    Args:
        title: Chart title
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    is_valid, error = validate_string(title, max_length=CHART_TITLE_MAX_LENGTH)
    if not is_valid:
        return is_valid, error
    
    # Check for injection patterns
    if any(bad in title.lower() for bad in ['<script', 'javascript:', 'onerror=', 'onclick=']):
        return False, "Title contains invalid content"
    
    return True, ""


def validate_axis_label(label: str) -> Tuple[bool, str]:
    """
    Validate axis label.
    
    Args:
        label: Axis label
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    return validate_string(label, max_length=AXIS_LABEL_MAX_LENGTH)


def validate_graph_name(name: str) -> Tuple[bool, str]:
    """
    Validate graph name for storage.
    
    Args:
        name: Graph name
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    is_valid, error = validate_string(name, max_length=GRAPH_NAME_MAX_LENGTH)
    if not is_valid:
        return is_valid, error
    
    # Allow alphanumeric, spaces, hyphens, underscores, dots
    if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', name):
        return False, "Graph name can only contain letters, numbers, spaces, hyphens, underscores, and dots"
    
    return True, ""


def validate_description(description: str) -> Tuple[bool, str]:
    """Validate description text."""
    return validate_string(description, max_length=DESCRIPTION_MAX_LENGTH)


# ============================================================================
# NUMBER LIST VALIDATION
# ============================================================================

def validate_number_list(data: Any, min_values: int = MIN_CHART_POINTS, 
                        max_values: int = MAX_CHART_POINTS) -> Tuple[bool, str, List[float]]:
    """
    Validate list of numbers with edge case handling.
    
    Args:
        data: Data to validate (can be list or comma-separated string)
        min_values: Minimum number of values
        max_values: Maximum number of values
        
    Returns:
        Tuple of (is_valid, error_message, parsed_list)
    """
    try:
        # Convert string to list
        if isinstance(data, str):
            # Handle edge cases: empty string, whitespace only
            if not data or not data.strip():
                return False, "Input cannot be empty", []
            
            # Split by comma and strip whitespace
            data = [x.strip() for x in data.split(',') if x.strip()]
        
        if not isinstance(data, list):
            return False, "Input must be a list or comma-separated values", []
        
        if len(data) == 0:
            return False, "Must provide at least one value", []
        
        if len(data) < min_values:
            return False, f"Need at least {min_values} values, got {len(data)}", []
        
        if len(data) > max_values:
            return False, f"Maximum {max_values} values allowed, got {len(data)}", []
        
        # Convert to float and validate each value
        parsed = []
        for i, item in enumerate(data):
            try:
                value = float(str(item).strip())
                
                # Check for valid IEEE 754 numbers
                if math.isnan(value) or math.isinf(value):
                    return False, f"Invalid number at position {i+1}: cannot be NaN or infinity", []
                
                # Check range
                if abs(value) > 1e50:
                    return False, f"Number at position {i+1} is out of practical range", []
                
                parsed.append(value)
            except ValueError:
                return False, f"Invalid number at position {i+1}: '{item}'", []
        
        return True, "", parsed
    except Exception as e:
        logger.error(f"Number list validation error: {e}")
        return False, f"Error processing input: {str(e)[:50]}", []


def validate_category_list(data: Any, min_categories: int = 2, 
                          max_categories: int = MAX_PIE_SLICES) -> Tuple[bool, str, List[str]]:
    """
    Validate category labels with comprehensive checks.
    
    Args:
        data: Category data (list or comma-separated string)
        min_categories: Minimum categories required
        max_categories: Maximum categories allowed
        
    Returns:
        Tuple of (is_valid, error_message, validated_list)
    """
    try:
        # Convert string to list
        if isinstance(data, str):
            if not data or not data.strip():
                return False, "Categories cannot be empty", []
            
            data = [x.strip() for x in data.split(',') if x.strip()]
        
        if not isinstance(data, list):
            return False, "Categories must be a list or comma-separated values", []
        
        if len(data) == 0:
            return False, "Must provide at least one category", []
        
        if len(data) < min_categories:
            return False, f"Need at least {min_categories} categories, got {len(data)}", []
        
        if len(data) > max_categories:
            return False, f"Maximum {max_categories} categories allowed, got {len(data)}", []
        
        # Validate each category
        validated = []
        seen = set()
        
        for i, cat in enumerate(data):
            cat_str = str(cat).strip()
            
            # Check empty
            if len(cat_str) == 0:
                return False, f"Category at position {i+1} cannot be empty", []
            
            # Check length
            if len(cat_str) > AXIS_LABEL_MAX_LENGTH:
                return False, f"Category at position {i+1} is too long (max {AXIS_LABEL_MAX_LENGTH} chars)", []
            
            # Check for duplicates
            if cat_str.lower() in seen:
                return False, f"Duplicate category: '{cat_str}'", []
            
            seen.add(cat_str.lower())
            validated.append(cat_str)
        
        return True, "", validated
    except Exception as e:
        logger.error(f"Category validation error: {e}")
        return False, f"Error processing categories: {str(e)[:50]}", []


# ============================================================================
# PROPORTION/DISTRIBUTION VALIDATION
# ============================================================================

def validate_proportions(data: Any) -> Tuple[bool, str, List[float]]:
    """
    Validate proportions for pie charts.
    All values must be positive.
    
    Args:
        data: Proportion data
        
    Returns:
        Tuple of (is_valid, error_message, parsed_list)
    """
    is_valid, error, parsed = validate_number_list(data, min_values=2, max_values=MAX_PIE_SLICES)
    
    if not is_valid:
        return is_valid, error, parsed
    
    # Check that all values are positive
    for i, val in enumerate(parsed):
        if val <= 0:
            return False, f"Proportion at position {i+1} must be positive (got {val})", []
    
    # Warn if sum is far from 1.0 (but allow flexibility)
    total = sum(parsed)
    if total == 0:
        return False, "All proportions are zero", []
    
    return True, "", parsed


def validate_histogram_bins(bins: Any) -> Tuple[bool, str, int]:
    """
    Validate histogram bin count.
    
    Args:
        bins: Number of bins
        
    Returns:
        Tuple of (is_valid, error_message, bin_count)
    """
    is_valid, error, bin_count = validate_integer(bins, min_value=HISTOGRAM_MIN_BINS, max_value=HISTOGRAM_MAX_BINS)
    if not is_valid:
        return False, f"Invalid bin count: {error}", 0
    
    return True, "", bin_count


# ============================================================================
# DICTIONARY VALIDATION
# ============================================================================

def validate_parameter_dict(params: dict, required_keys: List[str]) -> Tuple[bool, str]:
    """
    Validate parameter dictionary has required keys.
    
    Args:
        params: Parameter dictionary
        required_keys: List of required keys
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(params, dict):
        return False, "Parameters must be a dictionary"
    
    missing = [key for key in required_keys if key not in params or params[key] is None]
    if missing:
        return False, f"Missing required parameters: {', '.join(missing)}"
    
    return True, ""


def sanitize_dict(params: dict, max_depth: int = 3, max_keys: int = 100) -> dict:
    """
    Sanitize dictionary recursively with depth and key limits.
    
    Args:
        params: Dictionary to sanitize
        max_depth: Maximum recursion depth
        max_keys: Maximum number of keys
        
    Returns:
        Sanitized dictionary
    """
    if max_depth <= 0 or not isinstance(params, dict):
        return {}
    
    if len(params) > max_keys:
        logger.warning(f"Dictionary has too many keys ({len(params)}), truncating to {max_keys}")
        params = dict(list(params.items())[:max_keys])
    
    sanitized = {}
    for key, value in params.items():
        # Sanitize key
        if isinstance(key, str):
            safe_key = key[:AXIS_LABEL_MAX_LENGTH]
        else:
            safe_key = str(key)[:AXIS_LABEL_MAX_LENGTH]
        
        # Sanitize value
        if isinstance(value, str):
            sanitized[safe_key] = value[:500]
        elif isinstance(value, (int, float)):
            # Validate number range
            if not (math.isnan(value) or math.isinf(value)):
                sanitized[safe_key] = value
        elif isinstance(value, dict):
            sanitized[safe_key] = sanitize_dict(value, max_depth - 1, max_keys)
        elif isinstance(value, list):
            # Truncate list and filter valid items
            sanitized[safe_key] = [
                v for v in value[:100] 
                if isinstance(v, (str, int, float)) and not (isinstance(v, float) and (math.isnan(v) or math.isinf(v)))
            ]
        elif isinstance(value, bool):
            sanitized[safe_key] = value
        elif value is None:
            sanitized[safe_key] = None
        else:
            # Convert to string and truncate
            sanitized[safe_key] = str(value)[:500]
    
    return sanitized


# ============================================================================
# GRAPH DATA VALIDATION
# ============================================================================

def validate_line_graph_data(x_values: Any, y_values: Any, x_label: str, 
                             y_label: str, title: str) -> Tuple[bool, str]:
    """
    Validate data for line graph.
    
    Args:
        x_values: X-axis values
        y_values: Y-axis values
        x_label: X-axis label
        y_label: Y-axis label
        title: Graph title
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    # Validate labels and title
    for label, max_len in [(x_label, AXIS_LABEL_MAX_LENGTH), 
                           (y_label, AXIS_LABEL_MAX_LENGTH),
                           (title, CHART_TITLE_MAX_LENGTH)]:
        is_valid, error = validate_string(label, max_length=max_len)
        if not is_valid:
            return False, f"Invalid label/title: {error}"
    
    # Validate data
    x_valid, x_error, x_data = validate_number_list(x_values)
    if not x_valid:
        return False, f"Invalid X values: {x_error}"
    
    y_valid, y_error, y_data = validate_number_list(y_values)
    if not y_valid:
        return False, f"Invalid Y values: {y_error}"
    
    # Must have matching lengths
    if len(x_data) != len(y_data):
        return False, "X and Y values must have the same length"
    
    return True, ""


def validate_scatter_plot_data(x_values: Any, y_values: Any, x_label: str,
                               y_label: str, title: str) -> Tuple[bool, str]:
    """
    Validate data for scatter plot (same as line graph).
    """
    return validate_line_graph_data(x_values, y_values, x_label, y_label, title)


def validate_bar_chart_data(categories: Any, values: Any, y_label: str,
                           title: str) -> Tuple[bool, str]:
    """
    Validate data for bar chart.
    """
    # Validate categories
    cat_valid, cat_error, cat_data = validate_category_list(categories)
    if not cat_valid:
        return False, f"Invalid categories: {cat_error}"
    
    # Validate values
    val_valid, val_error, val_data = validate_number_list(values)
    if not val_valid:
        return False, f"Invalid values: {val_error}"
    
    # Must have matching counts
    if len(cat_data) != len(val_data):
        return False, "Categories and values must have matching counts"
    
    # Validate label and title
    for label, max_len in [(y_label, AXIS_LABEL_MAX_LENGTH), (title, CHART_TITLE_MAX_LENGTH)]:
        is_valid, error = validate_string(label, max_length=max_len)
        if not is_valid:
            return False, f"Invalid label/title: {error}"
    
    return True, ""


def validate_pie_chart_data(labels: Any, proportions: Any, title: str) -> Tuple[bool, str]:
    """
    Validate data for pie chart.
    """
    # Validate labels
    label_valid, label_error, label_data = validate_category_list(labels, max_categories=MAX_PIE_SLICES)
    if not label_valid:
        return False, f"Invalid labels: {label_error}"
    
    # Validate proportions
    prop_valid, prop_error, prop_data = validate_proportions(proportions)
    if not prop_valid:
        return False, f"Invalid proportions: {prop_error}"
    
    # Must have matching counts
    if len(label_data) != len(prop_data):
        return False, "Labels and proportions must have matching counts"
    
    # Validate title
    is_valid, error = validate_string(title, max_length=CHART_TITLE_MAX_LENGTH)
    if not is_valid:
        return False, f"Invalid title: {error}"
    
    return True, ""


def validate_histogram_data(data: Any, bins: Any, x_label: str,
                           y_label: str, title: str) -> Tuple[bool, str]:
    """
    Validate data for histogram.
    """
    # Validate data values
    data_valid, data_error, data_values = validate_number_list(data)
    if not data_valid:
        return False, f"Invalid data: {data_error}"
    
    # Validate bins
    bins_valid, bins_error, bin_count = validate_histogram_bins(bins)
    if not bins_valid:
        return False, f"Invalid bins: {bins_error}"
    
    # Validate labels and title
    for label, max_len in [(x_label, AXIS_LABEL_MAX_LENGTH),
                           (y_label, AXIS_LABEL_MAX_LENGTH),
                           (title, CHART_TITLE_MAX_LENGTH)]:
        is_valid, error = validate_string(label, max_length=max_len)
        if not is_valid:
            return False, f"Invalid label/title: {error}"
    
    return True, ""


def validate_box_whisker_data(data: Any, labels: Any, y_label: str,
                             title: str) -> Tuple[bool, str]:
    """
    Validate data for box-and-whisker plot.
    """
    if isinstance(data, str):
        # CSV format like "1,2,3,4,5|6,7,8,9,10"
        try:
            groups = data.split('|')
            if len(groups) == 0:
                return False, "No data provided"
        except:
            return False, "Invalid data format for box-and-whisker plot"
    elif isinstance(data, list):
        if len(data) == 0:
            return False, "No data provided"
        groups = data
    else:
        return False, "Data must be a string or list"
    
    # Validate labels
    label_valid, label_error, label_data = validate_category_list(labels, max_categories=50)
    if not label_valid:
        return False, f"Invalid labels: {label_error}"
    
    # Must have matching counts
    if len(label_data) != len(groups):
        return False, f"Expected {len(groups)} labels, got {len(label_data)}"
    
    # Validate labels and title
    for label, max_len in [(y_label, AXIS_LABEL_MAX_LENGTH), (title, CHART_TITLE_MAX_LENGTH)]:
        is_valid, error = validate_string(label, max_length=max_len)
        if not is_valid:
            return False, f"Invalid label/title: {error}"
    
    return True, ""


__all__ = [
    'validate_string', 'validate_number', 'validate_integer',
    'validate_chart_title', 'validate_axis_label', 'validate_graph_name',
    'validate_description', 'validate_number_list', 'validate_category_list',
    'validate_proportions', 'validate_histogram_bins', 'validate_parameter_dict',
    'sanitize_dict', 'validate_line_graph_data', 'validate_scatter_plot_data',
    'validate_bar_chart_data', 'validate_pie_chart_data', 'validate_histogram_data',
    'validate_box_whisker_data'
]
