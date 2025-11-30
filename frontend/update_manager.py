import httpx
import json
import asyncio
import os
from pathlib import Path
import flet as ft
from datetime import datetime
from dotenv import load_dotenv

# Ensure .env is loaded so API_BASE_URL / UPDATE_SERVER_URL are available
load_dotenv()

class UpdateManager:
    def __init__(self):
        self.current_version = "1.0.0" 
        # Base backend URL for updates: prefer explicit UPDATE_SERVER_URL, then API_BASE_URL, then localhost
        api_base = os.getenv("API_BASE_URL", "http://localhost:8000").rstrip("/")
        default_updates_url = f"{api_base}/api/v1/updates"
        self.update_server_url = os.getenv("UPDATE_SERVER_URL", default_updates_url).rstrip("/")
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            limits=httpx.Limits(max_keepalive_connections=2, max_connections=5)
        )
    
    async def check_for_updates(self) -> dict:
        """Check if updates are available"""
        try:
            response = await self.client.get(
                f"{self.update_server_url}/check",
                params={
                    "current_version": self.current_version,
                    "platform": "android"
                }
            )
            
            if response.status_code == 200:
                return response.json()
            
        except Exception as e:
            print(f"Update check failed: {e}")
            
        return {"update_available": False}
    
    async def download_update(self, download_url: str, progress_callback=None):
        """Download update file with progress"""
        try:
            response = await self.client.get(download_url, stream=True)
            
            if response.status_code == 200:
                file_size = int(response.headers.get("content-length", 0))
                downloaded = 0
                
                update_file = Path("update.apk")
                
                with open(update_file, "wb") as f:
                    async for chunk in response.aiter_bytes(8192):
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if progress_callback and file_size > 0:
                            progress = (downloaded / file_size) * 100
                            await progress_callback(progress)
                
                return str(update_file)
                
        except Exception as e:
            print(f"Download failed: {e}")
            
        return None
    
    def show_update_dialog(self, page: ft.Page, update_info: dict):
        """Show update available dialog"""
        
        def close_dialog(e):
            page.close(dialog)
            
        def start_update(e):
            page.close(dialog)
            # Start update download
            asyncio.create_task(self.handle_update(page, update_info))
        
        dialog = ft.AlertDialog(
            title=ft.Text("Update Available"),
            content=ft.Column([
                ft.Text(f"New version {update_info.get('version', 'Unknown')} is available!"),
                ft.Text(f"Current version: {self.current_version}"),
                ft.Text(""),
                ft.Text("What's new:"),
                ft.Text(update_info.get("changelog", "Bug fixes and improvements"), size=12),
            ], spacing=10),
            actions=[
                ft.TextButton("Later", on_click=close_dialog),
                ft.ElevatedButton("Update Now", on_click=start_update)
            ]
        )
        
        page.open(dialog)
    
    async def handle_update(self, page: ft.Page, update_info: dict):
        """Handle the update process"""
        
        # Show progress dialog
        progress_bar = ft.ProgressBar(width=300)
        progress_text = ft.Text("Downloading update...")
        
        progress_dialog = ft.AlertDialog(
            title=ft.Text("Updating App"),
            content=ft.Column([
                progress_text,
                progress_bar
            ], spacing=10),
            modal=True
        )
        
        page.open(progress_dialog)
        
        async def update_progress(progress):
            progress_bar.value = progress / 100
            progress_text.value = f"Downloading... {progress:.1f}%"
            page.update()
        
        # Download update
        download_url = update_info.get("download_url")
        if download_url:
            apk_path = await self.download_update(download_url, update_progress)
            
            if apk_path:
                progress_text.value = "Download complete! Installing..."
                page.update()
                
                # Install APK (Android will handle this)
                self.install_apk(apk_path)
            else:
                progress_text.value = "Download failed!"
                page.update()
        
        page.close(progress_dialog)
    
    def install_apk(self, apk_path: str):
        """Install APK file (Android handles this)"""
        try:
            # On Android, this will open the APK installer
            import subprocess
            subprocess.run(["am", "start", "-W", "-a", "android.intent.action.VIEW", 
                          "-d", f"file://{apk_path}", "-t", "application/vnd.android.package-archive"])
        except Exception as e:
            print(f"Install failed: {e}")


# Usage in main app
async def check_app_updates(page: ft.Page):
    """Check for app updates on startup"""
    update_manager = UpdateManager()
    update_info = await update_manager.check_for_updates()
    
    if update_info.get("update_available", False):
        update_manager.show_update_dialog(page, update_info)