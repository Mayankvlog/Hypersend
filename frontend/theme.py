"""
Zaply Theme - Light Blue Telegram Style
"""

# Telegram Perfect Colors
LIGHT_COLORS = {
    "accent": "#0088CC",          # Telegram Blue
    "accent_light": "#E7F5FF",    # Sky Blue
    "accent_hover": "#0077B5",    # Darker Blue
    "message_sent": "#EEFFDE",    # Light Green
    "message_received": "#FFFFFF", # White
    "chat_selected": "#F0F2F5",   # Light Gray
    "text_primary": "#000000",     # Black
    "text_secondary": "#65686B",   # Gray
    "text_tertiary": "#999999",    # Light Gray
    "bg_primary": "#FFFFFF",       # White
    "bg_secondary": "#F5F5F5",     # Light Gray
    "divider": "#E9EDEF",          # Divider Gray
    "success": "#31A24C",          # Green
    "error": "#E53935",            # Red
    "border": "#E0E0E0"            # Border Gray
}

DARK_COLORS = {
    "accent": "#0088CC",
    "accent_light": "#1E3A5F",
    "accent_hover": "#0077B5",
    "message_sent": "#2B5278",
    "message_received": "#1E1E1E",
    "chat_selected": "#2A2A2A",
    "text_primary": "#FFFFFF",
    "text_secondary": "#AAAAAA",
    "text_tertiary": "#666666",
    "bg_primary": "#0F0F0F",
    "bg_secondary": "#1A1A1A",
    "divider": "#2A2A2A",
    "success": "#31A24C",
    "error": "#E53935",
    "border": "#333333"
}

FONT_SIZES = {
    "xs": 10,
    "sm": 12,
    "base": 14,
    "lg": 16,
    "xl": 18,
    "2xl": 20,
    "3xl": 24
}

SPACING = {
    "xs": 2,
    "sm": 4,
    "md": 8,
    "lg": 12,
    "xl": 16,
    "2xl": 20,
    "3xl": 24
}

RADIUS = {
    "sm": 4,
    "md": 8,
    "lg": 12,
    "xl": 16,
    "2xl": 20,
    "full": 24
}

class ZaplyTheme:
    def __init__(self, dark_mode=False):
        self.dark_mode = dark_mode
        self.colors = DARK_COLORS if dark_mode else LIGHT_COLORS
