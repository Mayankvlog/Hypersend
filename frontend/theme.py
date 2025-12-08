import flet as ft

"""
Modern Design System for Zaply
Supports Minimal Clean (Light) and Elegant Dark modes
"""

# ============================================================================
# COLOR PALETTE - Light Mode (Minimal Clean)
# ============================================================================
LIGHT_COLORS = {
    # Background colors
    "bg_primary": "#FFFFFF",        # Pure white
    "bg_secondary": "#F8F9FA",      # Light gray background
    "bg_tertiary": "#F1F3F5",       # Card background
    
    # Text colors
    "text_primary": "#212529",      # Almost black
    "text_secondary": "#6C757D",    # Gray
    "text_tertiary": "#ADB5BD",     # Light gray
    "text_inverse": "#FFFFFF",      # White text
    
    # Accent colors
    "accent": "#0088CC",            # Telegram blue
    "accent_light": "#E7F5FF",      # Light blue background
    "accent_hover": "#0077B5",      # Darker blue on hover
    
    # Status colors
    "success": "#28A745",
    "warning": "#FFC107",
    "error": "#DC3545",
    "info": "#17A2B8",
    
    # Border and divider
    "border": "#DEE2E6",
    "divider": "#E9ECEF",
    
    # Shadows
    "shadow_sm": "#0000000A",       # 4% opacity
    "shadow_md": "#00000014",       # 8% opacity
    "shadow_lg": "#0000001F",       # 12% opacity
}

# ============================================================================
# COLOR PALETTE - Dark Mode (Elegant)
# ============================================================================
DARK_COLORS = {
    # Background colors
    "bg_primary": "#0E1621",        # Deep dark blue
    "bg_secondary": "#1A2332",      # Slightly lighter
    "bg_tertiary": "#212D3D",       # Card background
    
    # Text colors
    "text_primary": "#FFFFFF",      # Pure white
    "text_secondary": "#B0BAC9",    # Light gray
    "text_tertiary": "#6C7A8D",     # Muted gray
    "text_inverse": "#0E1621",      # Dark text
    
    # Accent colors
    "accent": "#3B82F6",            # Bright blue
    "accent_light": "#1E3A5F",      # Dark blue background
    "accent_hover": "#2563EB",      # Brighter blue on hover
    
    # Status colors
    "success": "#10B981",
    "warning": "#F59E0B",
    "error": "#EF4444",
    "info": "#06B6D4",
    
    # Border and divider
    "border": "#2D3748",
    "divider": "#374151",
    
    # Shadows
    "shadow_sm": "#00000033",       # 20% opacity
    "shadow_md": "#00000052",       # 32% opacity
    "shadow_lg": "#00000066",       # 40% opacity
}

# ============================================================================
# TYPOGRAPHY
# ============================================================================
FONT_SIZES = {
    "xs": 10,
    "sm": 12,
    "base": 14,
    "lg": 16,
    "xl": 18,
    "2xl": 20,
    "3xl": 24,
    "4xl": 30,
    "5xl": 36,
}

FONT_WEIGHTS = {
    "light": ft.FontWeight.W_300,
    "normal": ft.FontWeight.W_400,
    "medium": ft.FontWeight.W_500,
    "semibold": ft.FontWeight.W_600,
    "bold": ft.FontWeight.W_700,
}

# ============================================================================
# SPACING SYSTEM
# ============================================================================
SPACING = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 20,
    "2xl": 24,
    "3xl": 32,
    "4xl": 40,
    "5xl": 48,
}

# ============================================================================
# BORDER RADIUS
# ============================================================================
RADIUS = {
    "sm": 4,
    "md": 8,
    "lg": 12,
    "xl": 16,
    "2xl": 20,
    "full": 9999,
}

# ============================================================================
# ANIMATION DURATIONS
# ============================================================================
ANIMATION = {
    "fast": 150,        # Hover states
    "normal": 300,      # Transitions
    "slow": 500,        # Page changes
}

# ============================================================================
# THEME CLASS
# ============================================================================
class ZaplyTheme:
    """Zaply app theme manager"""
    
    def __init__(self, dark_mode: bool = False):
        self.dark_mode = dark_mode
        self.colors = DARK_COLORS if dark_mode else LIGHT_COLORS
        
    def get_color(self, key: str) -> str:
        """Get color by key"""
        return self.colors.get(key, "#000000")
    
    def get_flet_theme(self) -> ft.Theme:
        """Get Flet theme configuration"""
        if self.dark_mode:
            return ft.Theme(
                color_scheme_seed=self.colors["accent"],
                use_material3=True,
                visual_density=ft.ThemeVisualDensity.COMPACT,
            )
        else:
            return ft.Theme(
                color_scheme_seed=self.colors["accent"],
                use_material3=True,
                visual_density=ft.ThemeVisualDensity.COMPACT,
            )
    
    def toggle_mode(self):
        """Toggle between light and dark mode"""
        self.dark_mode = not self.dark_mode
        self.colors = DARK_COLORS if self.dark_mode else LIGHT_COLORS

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================
def create_card_shadow(dark_mode: bool = False) -> ft.BoxShadow:
    """Create standard card shadow"""
    colors = DARK_COLORS if dark_mode else LIGHT_COLORS
    return ft.BoxShadow(
        spread_radius=0,
        blur_radius=8,
        color=colors["shadow_md"],
        offset=ft.Offset(0, 2)
    )

def create_elevated_shadow(dark_mode: bool = False) -> ft.BoxShadow:
    """Create elevated shadow for FABs and important elements"""
    colors = DARK_COLORS if dark_mode else LIGHT_COLORS
    return ft.BoxShadow(
        spread_radius=0,
        blur_radius=16,
        color=colors["shadow_lg"],
        offset=ft.Offset(0, 4)
    )

def create_gradient_accent(dark_mode: bool = False) -> ft.LinearGradient:
    """Create accent gradient"""
    if dark_mode:
        return ft.LinearGradient(
            begin=ft.alignment.top_left,
            end=ft.alignment.bottom_right,
            colors=["#3B82F6", "#2563EB"]
        )
    else:
        return ft.LinearGradient(
            begin=ft.alignment.top_left,
            end=ft.alignment.bottom_right,
            colors=["#0088CC", "#0077B5"]
        )

# ============================================================================
# BACKWARDS COMPATIBILITY (for existing code)
# ============================================================================
PRIMARY_COLOR = LIGHT_COLORS["accent"]
SECONDARY_COLOR = LIGHT_COLORS["info"]
ACCENT_COLOR = LIGHT_COLORS["accent"]
BACKGROUND_LIGHT = LIGHT_COLORS["bg_secondary"]
BACKGROUND_DARK = DARK_COLORS["bg_primary"]
TEXT_PRIMARY = LIGHT_COLORS["text_primary"]
TEXT_SECONDARY = LIGHT_COLORS["text_secondary"]
BORDER_RADIUS = RADIUS["lg"]
SHADOW_COLOR = LIGHT_COLORS["shadow_md"]

# UI Constants
SPACING_SMALL = SPACING["sm"]
SPACING_MEDIUM = SPACING["md"]
SPACING_LARGE = SPACING["lg"]
PADDING_MOBILE = SPACING["lg"]
PADDING_DESKTOP = SPACING["2xl"]

# Font sizes
FONT_SIZE_SMALL = FONT_SIZES["sm"]
FONT_SIZE_NORMAL = FONT_SIZES["base"]
FONT_SIZE_LARGE = FONT_SIZES["lg"]
FONT_SIZE_TITLE = FONT_SIZES["2xl"]
FONT_SIZE_HEADING = FONT_SIZES["3xl"]

def get_theme(dark_mode=False):
    """Legacy theme getter for backwards compatibility"""
    theme = ZaplyTheme(dark_mode)
    return theme.get_flet_theme()


