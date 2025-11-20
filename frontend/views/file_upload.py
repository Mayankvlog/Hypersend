import flet as ft
import asyncio
import hashlib
import math
import os
from pathlib import Path
from typing import Optional, Callable
from frontend.theme import PRIMARY_COLOR, ACCENT_COLOR, SPACING_SMALL, SPACING_MEDIUM


class FileUploadView(ft.Container):
    """File upload view with chunked upload for files up to 40GB"""
    
    CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks
    MAX_PARALLEL = 4  # Parallel chunk uploads
    
    def __init__(self, page, api_client, chat_id: str, on_complete: Optional[Callable] = None):
        super().__init__()
        self.page = page
        self.api_client = api_client
        self.chat_id = chat_id
        self.on_complete = on_complete
        
        # Upload state
        self.selected_file_path: Optional[str] = None
        self.upload_id: Optional[str] = None
        self.is_uploading = False
        self.is_paused = False
        self.uploaded_chunks = set()
        self.total_chunks = 0
        self.file_size = 0
        
        # UI Components
        self.file_picker = ft.FilePicker(on_result=lambda e: self.page.run_task(self.on_file_picked, e))
        self.page.overlay.append(self.file_picker)
        
        self.file_info_text = ft.Text("No file selected", size=14, opacity=0.7)
        self.progress_bar = ft.ProgressBar(width=400, visible=False, value=0)
        self.progress_text = ft.Text("", size=12, opacity=0.6)
        self.speed_text = ft.Text("", size=12, opacity=0.6)
        self.error_text = ft.Text("", size=12, color="red", visible=False)
        
        self.upload_button = ft.ElevatedButton(
            "Upload",
            icon=ft.icons.UPLOAD_FILE,
            on_click=lambda e: self.page.run_task(self.start_upload),
            disabled=True,
            bgcolor=PRIMARY_COLOR
        )
        
        self.pause_button = ft.IconButton(
            icon=ft.icons.PAUSE,
            tooltip="Pause upload",
            on_click=self.pause_upload,
            visible=False
        )
        
        self.resume_button = ft.IconButton(
            icon=ft.icons.PLAY_ARROW,
            tooltip="Resume upload",
            on_click=lambda e: self.page.run_task(self.resume_upload),
            visible=False
        )
        
        self.cancel_button = ft.IconButton(
            icon=ft.icons.CANCEL,
            tooltip="Cancel upload",
            on_click=lambda e: self.page.run_task(self.cancel_upload),
            visible=False
        )
        
        # Layout
        self.content = ft.Column([
            ft.Text("Upload File", size=20, weight=ft.FontWeight.BOLD),
            ft.Divider(),
            
            # File selection
            ft.Container(
                content=ft.Column([
                    ft.ElevatedButton(
                        "Select File",
                        icon=ft.icons.FOLDER_OPEN,
                        on_click=lambda _: self.file_picker.pick_files(
                            allow_multiple=False,
                            dialog_title="Select file to upload (up to 40GB)"
                        )
                    ),
                    self.file_info_text,
                ], spacing=SPACING_SMALL),
                padding=SPACING_MEDIUM
            ),
            
            # Progress section
            ft.Container(
                content=ft.Column([
                    ft.Row([
                        self.upload_button,
                        self.pause_button,
                        self.resume_button,
                        self.cancel_button,
                    ], spacing=SPACING_SMALL),
                    self.progress_bar,
                    self.progress_text,
                    self.speed_text,
                    self.error_text,
                ], spacing=SPACING_SMALL),
                padding=SPACING_MEDIUM
            ),
            
            # Info
            ft.Container(
                content=ft.Column([
                    ft.Text("📋 Upload Info", size=14, weight=ft.FontWeight.BOLD),
                    ft.Text("• Max file size: 40 GB", size=12, opacity=0.7),
                    ft.Text("• Chunk size: 4 MB", size=12, opacity=0.7),
                    ft.Text("• Resumable: Yes", size=12, opacity=0.7),
                    ft.Text("• Parallel uploads: 4 streams", size=12, opacity=0.7),
                ], spacing=SPACING_SMALL),
                padding=SPACING_MEDIUM,
                bgcolor=ft.colors.SURFACE_VARIANT,
                border_radius=10
            )
        ], spacing=SPACING_MEDIUM, scroll=ft.ScrollMode.AUTO)
        
        self.expand = True
        self.padding = SPACING_MEDIUM
    
    async def on_file_picked(self, e: ft.FilePickerResultEvent):
        """Handle file selection"""
        if e.files and len(e.files) > 0:
            file = e.files[0]
            self.selected_file_path = file.path
            self.file_size = os.path.getsize(self.selected_file_path)
            
            # Calculate total chunks
            self.total_chunks = math.ceil(self.file_size / self.CHUNK_SIZE)
            
            # Update UI
            size_mb = self.file_size / (1024 * 1024)
            size_gb = self.file_size / (1024 * 1024 * 1024)
            
            if size_gb >= 1:
                size_str = f"{size_gb:.2f} GB"
            else:
                size_str = f"{size_mb:.2f} MB"
            
            self.file_info_text.value = f"📄 {file.name}\n📦 Size: {size_str}\n🔢 Chunks: {self.total_chunks}"
            self.file_info_text.opacity = 1.0
            self.upload_button.disabled = False
            self.error_text.visible = False
            
            # Check file size limit (40GB)
            max_size = 40 * 1024 * 1024 * 1024  # 40GB in bytes
            if self.file_size > max_size:
                self.error_text.value = f"⚠️ File too large! Maximum size is 40 GB"
                self.error_text.visible = True
                self.upload_button.disabled = True
            
            self.page.update()
    
    async def start_upload(self):
        """Start file upload"""
        if not self.selected_file_path:
            return
        
        try:
            self.is_uploading = True
            self.is_paused = False
            self.uploaded_chunks.clear()
            
            # Update UI
            self.upload_button.visible = False
            self.pause_button.visible = True
            self.cancel_button.visible = True
            self.progress_bar.visible = True
            self.progress_bar.value = 0
            self.error_text.visible = False
            self.page.update()
            
            # Compute file checksum (optional, can be slow for large files)
            # For now, skip checksum for files > 1GB
            checksum = None
            if self.file_size < 1024 * 1024 * 1024:  # < 1GB
                self.progress_text.value = "Computing checksum..."
                self.page.update()
                checksum = await self.compute_file_checksum()
            
            # Initialize upload
            self.progress_text.value = "Initializing upload..."
            self.page.update()
            
            filename = Path(self.selected_file_path).name
            mime_type = self.guess_mime_type(filename)
            
            response = await self.api_client.init_upload(
                filename=filename,
                size=self.file_size,
                mime=mime_type,
                chat_id=self.chat_id,
                checksum=checksum
            )
            
            self.upload_id = response["upload_id"]
            
            # Upload chunks
            await self.upload_chunks()
            
            # Complete upload
            if len(self.uploaded_chunks) == self.total_chunks and not self.is_paused:
                self.progress_text.value = "Finalizing upload..."
                self.page.update()
                
                complete_response = await self.api_client.complete_upload(self.upload_id)
                file_id = complete_response["file_id"]
                
                # Send message with file
                await self.api_client.send_message(
                    chat_id=self.chat_id,
                    text=f"📎 {filename}",
                    file_id=file_id
                )
                
                # Success
                self.progress_text.value = "✅ Upload complete!"
                self.progress_text.color = "green"
                self.speed_text.value = ""
                
                # Reset UI
                await asyncio.sleep(2)
                self.reset_upload_state()
                
                if self.on_complete:
                    self.on_complete(file_id)
            
        except Exception as e:
            self.error_text.value = f"⚠️ Upload failed: {str(e)}"
            self.error_text.visible = True
            self.is_uploading = False
            
            # Reset buttons
            self.upload_button.visible = True
            self.upload_button.disabled = False
            self.pause_button.visible = False
            self.resume_button.visible = False
            self.cancel_button.visible = False
            
            self.page.update()
    
    async def upload_chunks(self):
        """Upload file chunks with parallel processing"""
        import time
        
        semaphore = asyncio.Semaphore(self.MAX_PARALLEL)
        start_time = time.time()
        last_update_time = start_time
        last_uploaded_bytes = 0
        
        async def upload_single_chunk(chunk_index: int, chunk_data: bytes):
            async with semaphore:
                if self.is_paused or not self.is_uploading:
                    return
                
                # Compute chunk checksum
                chunk_checksum = hashlib.sha256(chunk_data).hexdigest()
                
                # Retry logic
                max_retries = 3
                for attempt in range(max_retries):
                    try:
                        await self.api_client.upload_chunk(
                            upload_id=self.upload_id,
                            chunk_index=chunk_index,
                            chunk_data=chunk_data,
                            checksum=chunk_checksum
                        )
                        
                        self.uploaded_chunks.add(chunk_index)
                        
                        # Update progress
                        progress = len(self.uploaded_chunks) / self.total_chunks
                        self.progress_bar.value = progress
                        
                        # Calculate speed
                        nonlocal last_update_time, last_uploaded_bytes
                        current_time = time.time()
                        if current_time - last_update_time >= 1.0:  # Update every second
                            uploaded_bytes = len(self.uploaded_chunks) * self.CHUNK_SIZE
                            bytes_since_last = uploaded_bytes - last_uploaded_bytes
                            elapsed = current_time - last_update_time
                            speed_mbps = (bytes_since_last / elapsed) / (1024 * 1024)
                            
                            uploaded_mb = uploaded_bytes / (1024 * 1024)
                            total_mb = self.file_size / (1024 * 1024)
                            
                            self.progress_text.value = f"Uploaded: {len(self.uploaded_chunks)}/{self.total_chunks} chunks ({uploaded_mb:.1f}/{total_mb:.1f} MB)"
                            self.speed_text.value = f"Speed: {speed_mbps:.2f} MB/s"
                            
                            last_update_time = current_time
                            last_uploaded_bytes = uploaded_bytes
                            
                            self.page.update()
                        
                        break  # Success
                    
                    except Exception as e:
                        if attempt == max_retries - 1:
                            raise
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        # Read and upload chunks
        with open(self.selected_file_path, "rb") as f:
            tasks = []
            for chunk_index in range(self.total_chunks):
                if self.is_paused or not self.is_uploading:
                    break
                
                # Read chunk
                chunk_data = f.read(self.CHUNK_SIZE)
                
                # Create upload task
                task = upload_single_chunk(chunk_index, chunk_data)
                tasks.append(task)
            
            # Wait for all uploads
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def compute_file_checksum(self) -> str:
        """Compute SHA-256 checksum of entire file"""
        hasher = hashlib.sha256()
        with open(self.selected_file_path, "rb") as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def pause_upload(self, e):
        """Pause upload"""
        self.is_paused = True
        self.pause_button.visible = False
        self.resume_button.visible = True
        self.progress_text.value = "⏸️ Upload paused"
        self.page.update()
    
    async def resume_upload(self):
        """Resume upload"""
        self.is_paused = False
        self.resume_button.visible = False
        self.pause_button.visible = True
        self.progress_text.value = "Resuming upload..."
        self.page.update()
        
        # Continue uploading remaining chunks
        await self.upload_chunks()
        
        # Complete if all chunks uploaded
        if len(self.uploaded_chunks) == self.total_chunks:
            await self.start_upload()
    
    async def cancel_upload(self):
        """Cancel upload"""
        if self.upload_id:
            try:
                await self.api_client.cancel_upload(self.upload_id)
            except:
                pass
        
        self.is_uploading = False
        self.is_paused = False
        self.reset_upload_state()
        
        self.progress_text.value = "❌ Upload cancelled"
        self.progress_text.color = "red"
        self.page.update()
        
        await asyncio.sleep(2)
        self.progress_text.value = ""
        self.page.update()
    
    def reset_upload_state(self):
        """Reset upload state"""
        self.upload_id = None
        self.is_uploading = False
        self.is_paused = False
        self.uploaded_chunks.clear()
        
        # Reset UI
        self.upload_button.visible = True
        self.upload_button.disabled = True
        self.pause_button.visible = False
        self.resume_button.visible = False
        self.cancel_button.visible = False
        self.progress_bar.visible = False
        self.progress_bar.value = 0
        self.progress_text.value = ""
        self.progress_text.color = None
        self.speed_text.value = ""
        self.selected_file_path = None
        self.file_info_text.value = "No file selected"
        self.file_info_text.opacity = 0.7
        
        self.page.update()
    
    def guess_mime_type(self, filename: str) -> str:
        """Guess MIME type from filename"""
        ext = Path(filename).suffix.lower()
        mime_types = {
            # Video
            ".mp4": "video/mp4",
            ".mov": "video/quicktime",
            ".avi": "video/x-msvideo",
            ".mkv": "video/x-matroska",
            ".webm": "video/webm",
            
            # Images
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".gif": "image/gif",
            ".webp": "image/webp",
            
            # Documents
            ".pdf": "application/pdf",
            ".doc": "application/msword",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xls": "application/vnd.ms-excel",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".ppt": "application/vnd.ms-powerpoint",
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            
            # Archives
            ".zip": "application/zip",
            ".rar": "application/x-rar-compressed",
            ".7z": "application/x-7z-compressed",
            ".tar": "application/x-tar",
            ".gz": "application/gzip",
            
            # Text
            ".txt": "text/plain",
            ".json": "application/json",
            ".xml": "application/xml",
            ".csv": "text/csv",
        }
        
        return mime_types.get(ext, "application/octet-stream")
