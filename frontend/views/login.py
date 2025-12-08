import flet as ft
from theme import SPACING_MEDIUM, SPACING_LARGE, BORDER_RADIUS


class LoginView(ft.Container):
    def __init__(self, page, api_client, on_success, on_forgot_password):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.on_success = on_success
        self.on_forgot_password = on_forgot_password
        self.is_login_mode = True
        
        # UI Elements
        self.name_field = ft.TextField(
            label="Name",
            border_radius=BORDER_RADIUS,
            visible=False,
            keyboard_type=ft.KeyboardType.NAME,
            read_only=False,
            disabled=False
        )
        self.email_field = ft.TextField(
            label="Email",
            border_radius=BORDER_RADIUS,
            keyboard_type=ft.KeyboardType.EMAIL,
            autofocus=True,
            read_only=False,
            disabled=False
        )
        self.password_field = ft.TextField(
            label="Password",
            password=True,
            can_reveal_password=True,
            on_change=lambda e: self._handle_password_change()
        )
        
        # Password strength indicator
        self.password_strength = ft.Container(
            content=ft.Column([
                ft.Text(
                    "Password Strength:",
                    size=12,
                    color=ft.Colors.BLUE_GREY_600
                ),
                ft.Container(
                    height=4,
                    bgcolor=ft.Colors.BLUE_GREY_200,
                    border_radius=2
                ),
                ft.Text(
                    "",
                    size=10,
                    color=ft.Colors.BLUE_GREY_500
                )
            ], spacing=5),
            visible=False
        )
        self.error_text = ft.Text("", color=ft.Colors.RED_400, visible=False)
        self.submit_button = ft.ElevatedButton(
            "Login",
            on_click=lambda e: self.page.run_task(self.handle_submit, e),
            width=200,
            height=45
        )
        self.toggle_button = ft.TextButton(
            "Don't have an account? Register",
            on_click=self.toggle_mode
        )
        self.forgot_password_button = ft.TextButton(
            "Forgot Password?",
            on_click=on_forgot_password,
            visible=True  # Only visible in login mode
        )
        
        # Layout
        self.content = ft.Column(
                [
                self.name_field,
                self.email_field,
                self.password_field,
                self.password_strength,
                self.error_text,
                ft.Container(height=20),
                self.submit_button,
                self.forgot_password_button,
                self.toggle_button,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=SPACING_MEDIUM
        )
        
        self.padding = SPACING_LARGE
        self.expand = True
    
    def _handle_password_change(self):
        """Handle password field changes and update strength indicator"""
        password = self.password_field.value or ""
        
        if not self.is_login_mode and password:
            # Show strength indicator for registration
            self.password_strength.visible = True
            
            # Calculate strength
            strength = 0
            requirements = []
            
            if len(password) >= 8:
                strength += 25
                requirements.append("✓ 8+ characters")
            else:
                requirements.append("✗ 8+ characters")
            
            if any(c.isupper() for c in password):
                strength += 25
                requirements.append("✓ Uppercase")
            else:
                requirements.append("✗ Uppercase")
            
            if any(c.islower() for c in password):
                strength += 25
                requirements.append("✓ Lowercase")
            else:
                requirements.append("✗ Lowercase")
            
            if any(c.isdigit() for c in password):
                strength += 25
                requirements.append("✓ Number")
            else:
                requirements.append("✗ Number")
            
            # Update strength bar
            strength_colors = {
                0: ft.Colors.RED_400,
                25: ft.Colors.ORANGE_400,
                50: ft.Colors.YELLOW_400,
                75: ft.Colors.BLUE_400,
                100: ft.Colors.GREEN_400
            }
            
            strength_labels = {
                0: "Very Weak",
                25: "Weak", 
                50: "Fair",
                75: "Good",
                100: "Strong"
            }
            
            # Update the strength indicator
            strength_bar = self.password_strength.content.controls[1]
            strength_text = self.password_strength.content.controls[2]
            
            strength_bar.bgcolor = strength_colors.get(strength, ft.Colors.RED_400)
            strength_text.value = strength_labels.get(strength, "Very Weak")
            strength_text.color = strength_colors.get(strength, ft.Colors.RED_400)
            
        else:
            self.password_strength.visible = False
        
        self.page.update()
    
    def toggle_mode(self, e):
        """Toggle between login and register mode"""
        self.is_login_mode = not self.is_login_mode
        if self.is_login_mode:
            self.name_field.visible = False
            self.password_strength.visible = False
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
    
    def validate_password(self, password: str) -> tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        return True, "Password is valid"
    
    async def handle_submit(self, e):
        """Handle login/register submission"""
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
        
        # For registration, validate password strength
        if not self.is_login_mode:
            is_valid, error_msg = self.validate_password(password)
            if not is_valid:
                self.error_text.value = error_msg
                self.error_text.visible = True
                self.page.update()
                return
        
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
                    self.page.update()
                    return
                
                await self.api_client.register(name, email, password)
                await self.api_client.login(email, password)
                user = await self.api_client.get_current_user()
                self.on_success(user)
        except Exception as ex:
            self.error_text.value = f"Error: {str(ex)}"
            self.error_text.visible = True
            self.page.update()
