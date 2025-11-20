import flet as ft
from frontend.theme import PRIMARY_COLOR, SPACING_MEDIUM, SPACING_LARGE, BORDER_RADIUS


class LoginView(ft.Container):
    def __init__(self, page, api_client, on_success):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.on_success = on_success
        self.is_login_mode = True
        
        # UI Elements
        self.name_field = ft.TextField(
            label="Name",
            border_radius=BORDER_RADIUS,
            visible=False
        )
        self.email_field = ft.TextField(
            label="Email",
            border_radius=BORDER_RADIUS,
            keyboard_type=ft.KeyboardType.EMAIL
        )
        self.password_field = ft.TextField(
            label="Password",
            border_radius=BORDER_RADIUS,
            password=True,
            can_reveal_password=True
        )
        self.error_text = ft.Text("", color=ft.colors.RED_400, visible=False)
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
        
        # Layout
        self.content = ft.Column(
                [
                self.name_field,
                self.email_field,
                self.password_field,
                self.error_text,
                ft.Container(height=20),
                self.submit_button,
                self.toggle_button,
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=SPACING_MEDIUM
        )
        
        self.padding = SPACING_LARGE
        self.expand = True
    
    def toggle_mode(self, e):
        """Toggle between login and register"""
        self.is_login_mode = not self.is_login_mode
        self.name_field.visible = not self.is_login_mode
        self.submit_button.text = "Login" if self.is_login_mode else "Register"
        self.toggle_button.text = "Don't have an account? Register" if self.is_login_mode else "Already have an account? Login"
        self.error_text.visible = False
        self.page.update()
    
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
