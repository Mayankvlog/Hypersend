#!/usr/bin/env python3
"""
Test script to verify text input is working correctly
"""
import flet as ft
import asyncio

def test_text_input():
    """Test basic text input functionality"""
    print("🧪 Testing Text Input Functionality...")
    
    def main(page: ft.Page):
        page.title = "Text Input Test"
        page.window.width = 400
        page.window.height = 600
        
        # Create a simple message input field
        message_input = ft.TextField(
            hint_text="Type something...",
            border=ft.InputBorder.NONE,
            filled=True,
            expand=True,
            multiline=True,
            min_lines=1,
            max_lines=5,
            keyboard_type=ft.KeyboardType.TEXT,
            autofocus=True,
            read_only=False,
            disabled=False,
        )
        
        output_text = ft.Text("", size=14, color="green")
        
        def on_text_change(e):
            output_text.value = f"✅ Input detected: '{message_input.value}'"
            page.update()
        
        # Attach change event listener
        message_input.on_change = on_text_change
        
        # Create main view
        main_view = ft.View("/", [
            ft.Container(
                content=ft.Column([
                    ft.Text("📝 Text Input Test", size=20, weight=ft.FontWeight.BOLD),
                    ft.Divider(),
                    ft.Text("Try typing in the field below:", size=14),
                    message_input,
                    ft.Divider(),
                    output_text,
                    ft.Text(
                        "✅ If you can type, text input is working correctly!",
                        size=12,
                        color="blue"
                    )
                ], spacing=10),
                padding=20,
                expand=True
            )
        ])
        
        page.views.clear()
        page.views.append(main_view)
        page.view_insets = True
        
        # Focus the input
        async def focus_input():
            await asyncio.sleep(0.1)
            try:
                message_input.focus()
                print("✅ Message input focused successfully")
            except Exception as e:
                print(f"⚠️ Could not focus: {e}")
        
        page.run_task(focus_input)
        page.update()
    
    # Run the test
    try:
        ft.app(target=main, name="TextInputTest")
        print("✅ Text input test completed")
        return True
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

if __name__ == "__main__":
    test_text_input()
