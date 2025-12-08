import flet as ft
import sys
import os

# Add parent directory to sys.path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from theme import ZaplyTheme, FONT_SIZES, SPACING, RADIUS


class LoginView(ft.Container):
    def __init__(self, page, api_client, on_success, on_forgot_password, dark_mode=False):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.on_success = on_success
        self.on_forgot_password = on_forgot_password
        self.is_login_mode = True
        
        # Theme
        self.theme = ZaplyTheme(dark_mode=dark_mode)
        self.dark_mode = dark_mode
        colors_palette = self.theme.colors
        
        # UI Elements - Minimal Clean Design
        self.name_field = ft.TextField(
            label="Name",
            border_radius=RADIUS["md"],
            visible=False,
            keyboard_type=ft.KeyboardType.NAME,
            text_size=FONT_SIZES["base"],
            border_color=colors_palette["border"],
            focused_border_color=colors_palette["accent"]
        )
        
        self.email_field = ft.TextField(
            label="Email",
            border_radius=RADIUS["md"],
            keyboard_type=ft.KeyboardType.EMAIL,
            autofocus=True,
            text_size=FONT_SIZES["base"],
            border_color=colors_palette["border"],
            focused_border_color=colors_palette["accent"]
        )
        
        self.password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            border_radius=RADIUS["md"],
            text_size=FONT_SIZES["base"],
            border_color=colors_palette["border"],
            focused_border_color=colors_palette["accent"]
        )
        
        self.error_text = ft.Text(
            "",
            color=colors_palette["error"],
            size=FONT_SIZES["sm"],
            visible=False
        )
        
        self.submit_button = ft.ElevatedButton(
            "Login",
            on_click=lambda e: self.page.run_task(self.handle_submit, e),
            width=300,
            height=48,
            style=ft.ButtonStyle(
                bgcolor=colors_palette["accent"],
                color=colors_palette["text_inverse"],
                shape=ft.RoundedRectangleBorder(radius=RADIUS["md"])
            )
        )
        
        self.toggle_button = ft.TextButton(
            "Don't have an account? Register",
            on_click=self.toggle_mode,
            style=ft.ButtonStyle(
                color=colors_palette["accent"]
            )
        )
        
        self.forgot_password_button = ft.TextButton(
            "Forgot Password?",
            on_click=on_forgot_password,
            visible=True,
            style=ft.ButtonStyle(
                color=colors_palette["text_secondary"]
            )
        )
        
        # Theme toggle button
        self.theme_toggle = ft.IconButton(
            icon=ft.Icons.DARK_MODE if not self.dark_mode else ft.Icons.LIGHT_MODE,
            icon_color=colors_palette["text_primary"],
            tooltip="Toggle theme",
            on_click=lambda e: self.toggle_theme()
        )
        
        # Logo/Title
        title_text = ft.Text(
            "Zaply",
            size=FONT_SIZES["5xl"],
            weight=ft.FontWeight.W_700,
            color=colors_palette["accent"]
        )
        
        subtitle_text = ft.Text(
            "Your personal messaging space",
            size=FONT_SIZES["base"],
            color=colors_palette["text_secondary"],
            text_align=ft.TextAlign.CENTER
        )
        
        # Layout - Centered, Minimal
        self.content = ft.Container(
            content=ft.Column([
                # Theme toggle at top right
                ft.Row([
                    ft.Container(expand=True),
                    self.theme_toggle
                ]),
                # Centered login form
                ft.Container(
                    content=ft.Column([
                        # Logo/Title
                        title_text,
                        subtitle_text,
                        ft.Container(height=SPACING["3xl"]),
                        
                        # Form fields
                        self.name_field,
                        self.email_field,
                        self.password_field,
                        self.error_text,
                        
                        ft.Container(height=SPACING["md"]),
                        
                        # Actions
                        self.submit_button,
                        self.forgot_password_button,
                        self.toggle_button,
                    ],
                    horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                    spacing=SPACING["md"]),
                    alignment=ft.alignment.center,
                    expand=True
                )
            ]),
            padding=ft.padding.all(SPACING["2xl"]),
            bgcolor=colors_palette["bg_primary"],
            expand=True
        )
        
        self.bgcolor = colors_palette["bg_primary"]
        self.expand = True
    
    def toggle_theme(self):
        """Toggle between light and dark mode"""
        self.dark_mode = not self.dark_mode
        self.theme = ZaplyTheme(dark_mode=self.dark_mode)
        self.page.theme_mode = ft.ThemeMode.DARK if self.dark_mode else ft.ThemeMode.LIGHT
        
        # Rebuild UI with new theme
        self.__init__(self.page, self.api_client, self.on_success, self.on_forgot_password, self.dark_mode)
        self.page.update()
    
    def toggle_mode(self, e):
        """Toggle between login and register mode"""
        self.is_login_mode = not self.is_login_mode
        if self.is_login_mode:
            self.name_field.visible = False
            self.submit_button.text = "Login"
            self.toggle_button.text = "Don't have an account? Register"
            self.forgot_password_button.visible = True
        else:
            self.name_field.visible = True
            self.submit_button.text = "Register"
            self.toggle_button.text = "Already have an account? Login"
            self.forgot_password_button.visible = False
        self.page.update()
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    async def handle_submit(self, e):
        """Handle login/register submission"""
        colors_palette = self.theme.colors
        
        self.error_text.visible = False
        email = self.email_field.value
        password = self.password_field.value
        
        if not email or not password:
            self.error_text.value = "Please fill all fields"
            self.error_text.visible = True
            self.page.update()
            return
        
        # Validate email format
        if not self.validate_email(email):
            self.error_text.value = "Please enter a valid email address"
            self.error_text.visible = True
            self.page.update()
            return
        
        # Show loading state
        original_text = self.submit_button.text
        self.submit_button.text = "Loading..."
        self.submit_button.disabled = True
        self.page.update()
        
        try:
            if self.is_login_mode:
                # Login
                await self.api_client.login(email, password)
                user = await self.api_client.get_current_user()
                self.on_success(user)
            else:
                # Register
                name = self.name_field.value
                if not name:
                    self.error_text.value = "Please enter your name"
                    self.error_text.visible = True
                    self.submit_button.text = original_text
                    self.submit_button.disabled = False
                    self.page.update()
                    return
                
                await self.api_client.register(name, email, password)
                await self.api_client.login(email, password)
                user = await self.api_client.get_current_user()
                self.on_success(user)
        except Exception as ex:
            self.error_text.value = f"Error: {str(ex)}"
            self.error_text.visible = True
            self.submit_button.text = original_text
            self.submit_button.disabled = False
            self.page.update()


