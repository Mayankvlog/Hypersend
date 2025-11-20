import flet as ft

# Design tokens
PRIMARY_COLOR = "#1F8EF1"  # Electric blue
ACCENT_COLOR = "#00D1B2"  # Teal
DARK_SURFACE = "#0B1220"
LIGHT_SURFACE = "#0D0D0D"
TEXT_LIGHT = "#0D0D0D"
TEXT_DARK = "#131314"
TEXT_BLACK = "#000000"
BORDER_RADIUS = 12
SHADOW_COLOR = "#00000020"

# Theme configuration
def get_theme(dark_mode=True):
    """Get Flet theme configuration"""
    if dark_mode:
        return ft.Theme(
            color_scheme_seed=PRIMARY_COLOR,
            use_material3=True,
            color_scheme=ft.ColorScheme(
                primary=PRIMARY_COLOR,
                secondary=ACCENT_COLOR,
                surface=DARK_SURFACE,
                background=DARK_SURFACE,
                on_primary=TEXT_LIGHT,
                on_surface=TEXT_LIGHT,
            ),
            visual_density=ft.ThemeVisualDensity.COMPACT,
        )
    else:
        return ft.Theme(
            color_scheme_seed=PRIMARY_COLOR,
            use_material3=True,
            color_scheme=ft.ColorScheme(
                primary=PRIMARY_COLOR,
                secondary=ACCENT_COLOR,
                surface=LIGHT_SURFACE,
                background=LIGHT_SURFACE,
                on_primary=TEXT_LIGHT,
                on_surface=TEXT_DARK,
            ),
            visual_density=ft.ThemeVisualDensity.COMPACT,
        )


# UI Constants
SPACING_SMALL = 8
SPACING_MEDIUM = 16
SPACING_LARGE = 24
PADDING_MOBILE = 16
PADDING_DESKTOP = 24

# Font sizes
FONT_SIZE_SMALL = 12
FONT_SIZE_NORMAL = 14
FONT_SIZE_LARGE = 16
FONT_SIZE_TITLE = 20
FONT_SIZE_HEADING = 24
