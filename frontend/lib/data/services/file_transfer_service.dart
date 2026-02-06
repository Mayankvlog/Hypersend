import 'dart:typed_data';
import 'dart:async';
import 'dart:io';
import 'package:crypto/crypto.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart' show debugPrint, kIsWeb;
import 'package:path_provider/path_provider.dart';
import 'api_service.dart';
import '../../core/constants/api_constants.dart';

class FileTransferService {
  final ApiService _api;
  final List<FileTransfer> _transfers = [];
  Timer? _cleanupTimer;

  FileTransferService(this._api) {
    // Initialize periodic cleanup of completed transfers
    _cleanupTimer = Timer.periodic(const Duration(minutes: 5), (_) => _cleanupCompleted());
  }

  List<FileTransfer> get activeTransfers => _transfers;

  void _cleanupCompleted() {
    _transfers.removeWhere((transfer) {
      // Remove completed transfers to prevent memory leaks
      return transfer.status == TransferStatus.completed;
    });
  }

  void dispose() {
    _cleanupTimer?.cancel();
  }

  /// WhatsApp-style ephemeral file upload with direct S3 upload.
  /// Server provides pre-signed URL, client uploads directly to S3.
  /// Files are stored temporarily (24h TTL) then auto-deleted.
  Future<void> pickAndUpload({
    required String chatId,
    required Function(double) onProgress,
  }) async {
    final result = await FilePicker.platform.pickFiles(
      withReadStream: true,
      type: FileType.any,
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty) return;

    final file = result.files.single;
    if (file.name.isEmpty || file.size <= 0) {
      throw Exception('Invalid file selection');
    }

    // Check against 15GB limit
    if (file.size > ApiConstants.maxFileSizeBytes) {
      final sizeGB = file.size / (1024 * 1024 * 1024);
      throw Exception('File size (${sizeGB.toStringAsFixed(2)}GB) exceeds 15GB limit');
    }

    final stream = file.readStream ?? (file.bytes != null ? Stream.value(file.bytes!) : null);

    await uploadFileStream(
      chatId: chatId,
      fileName: file.name,
      fileSize: file.size,
      mime: _guessMime(file.extension),
      stream: stream,
      onProgress: onProgress,
    );
  }

  String _guessMime(String? ext) {
    final e = (ext ?? '').toLowerCase();
    switch (e) {
      case 'jpg':
      case 'jpeg':
        return 'image/jpeg';
      case 'png':
        return 'image/png';
      case 'pdf':
        return 'application/pdf';
      case 'mp4':
        return 'video/mp4';
      case 'zip':
        return 'application/zip';
      default:
        return 'application/octet-stream';
    }
  }

  Future<void> uploadFileStream({
    required String chatId,
    required String fileName,
    required int fileSize,
    required String mime,
    required Stream<List<int>>? stream,
    required Function(double) onProgress,
  }) async {
    if (stream == null) {
      throw Exception('File stream not available');
    }

    final transfer = FileTransfer(
      id: DateTime.now().millisecondsSinceEpoch.toString(),
      fileName: fileName,
      fileSize: fileSize,
      filePath: '',
      chatId: chatId,
      status: TransferStatus.uploading,
      direction: TransferDirection.upload,
      progress: 0,
    );
    _transfers.add(transfer);

    try {
      // WHATSAPP ARCHITECTURE: Get pre-signed S3 URL for direct upload
      final init = await _api.initUpload(
        filename: fileName,
        size: fileSize,
        mime: mime,
        chatId: chatId,
      );

      final uploadUrl = init['upload_url'] as String?;
      if (uploadUrl == null) {
        throw Exception('Failed to get upload URL from server');
      }

      // WHATSAPP ARCHITECTURE: Upload directly to S3 using pre-signed URL
      debugPrint('[WHATSAPP_UPLOAD] Uploading directly to S3: $uploadUrl');
      
      // Convert stream to bytes for direct S3 upload
      final bytesBuilder = BytesBuilder();
      await for (final chunk in stream) {
        bytesBuilder.add(chunk);
      }
      
      final fileBytes = bytesBuilder.takeBytes();
      
      // Create HTTP request for S3 upload
      final client = HttpClient();
      final request = HttpRequest('PUT', Uri.parse(uploadUrl));
      request.headers['Content-Type'] = mime;
      request.body = fileBytes;
      
      // Upload to S3
      final response = await client.send(request);
      
      if (response.statusCode != 200) {
        throw Exception('S3 upload failed: ${response.statusCode}');
      }
      
      // WHATSAPP ARCHITECTURE: Notify server of successful upload
      await _api.completeUpload(uploadId: init['uploadId'] as String);
      
      _markCompleted(transfer.id);
      debugPrint('[WHATSAPP_UPLOAD] File uploaded successfully to S3');
      
    } catch (e) {
      _markFailed(transfer.id);
      debugPrint('[WHATSAPP_UPLOAD] Upload failed: $e');
      rethrow;
    }
  }

  /// Download file to a local path (desktop/mobile).
  Future<void> downloadFile({
    required String fileId,
    required String fileName,
    required String savePath,
    required Function(double) onProgress,
  }) async {
    // Enhanced download path generation with proper validation
    String actualSavePath;
    if (kIsWeb) {
      throw Exception('File download not supported on web platform');
    } else {
      // For native platforms, use karo directory as specified
      Directory? directory;
      try {
        // Try to use karo directory first
        directory = Directory('/karo');
        if (!await directory.exists()) {
          await directory.create(recursive: true);
        }
        debugPrint('[FILE_TRANSFER] Using karo directory: ${directory.path}');
      } catch (e) {
        debugPrint('[FILE_TRANSFER] Could not create karo directory: $e');
        // Fallback to downloads directory
        try {
          directory = await getDownloadsDirectory();
          debugPrint('[FILE_TRANSFER] Primary downloads directory: ${directory?.path}');
        } catch (e) {
          debugPrint('[FILE_TRANSFER] Could not get downloads directory: $e');
        }
        
        // Fallback to application documents if downloads directory fails
        if (directory == null) {
          try {
            directory = await getApplicationDocumentsDirectory();
            debugPrint('[FILE_TRANSFER] Using fallback directory: ${directory.path}');
          } catch (e) {
            debugPrint('[FILE_TRANSFER] Could not get application directory: $e');
            throw Exception('Unable to determine save location for downloaded file');
          }
        }
      }
      
      // Sanitize and construct final path
      final sanitizedSavePath = _sanitizeFileName(savePath);
      actualSavePath = '${directory.path}/$sanitizedSavePath';
      
       // Enhanced path validation
       final file = File(actualSavePath);
       final parentDir = file.parent;
       
       debugPrint('[FILE_TRANSFER] Final save path: $actualSavePath');
       debugPrint('[FILE_TRANSFER] Parent directory exists: ${await parentDir.exists()}');
       debugPrint('[FILE_TRANSFER] Parent directory path: ${parentDir.path}');
       
       // CRITICAL FIX: Ensure parent directory exists with proper error handling
       try {
         if (!await parentDir.exists()) {
           debugPrint('[FILE_TRANSFER] Creating parent directory: ${parentDir.path}');
           await parentDir.create(recursive: true);
         }
         
         // CRITICAL FIX: Test write permissions more robustly
         final testFile = File('${parentDir.path}/.download_test_${DateTime.now().millisecondsSinceEpoch}');
         try {
           await testFile.writeAsString('test');
           final writtenContent = await testFile.readAsString();
           if (writtenContent != 'test') {
             throw Exception('Directory write test failed - content mismatch');
           }
           await testFile.delete();
           debugPrint('[FILE_TRANSFER] Directory is writable: ✅');
         } catch (writeError) {
           debugPrint('[FILE_TRANSFER] Write permission test failed: $writeError');
           throw Exception('Directory is not writable: $writeError');
         }
       } catch (e) {
         debugPrint('[FILE_TRANSFER] Directory creation/writability failed: $e');
         throw Exception('Cannot create or write to download directory: $e');
       }
    }

    final transfer = FileTransfer(
      id: fileId,
      fileName: fileName,
      fileSize: 0,
      filePath: actualSavePath,
      chatId: '',
      status: TransferStatus.downloading,
      direction: TransferDirection.download,
      progress: 0,
    );
    _transfers.add(transfer);

    try {
      debugPrint('[FILE_TRANSFER] Getting file info to determine download strategy');
      debugPrint('[FILE_TRANSFER] Download path: $actualSavePath');
      
      // Get file info first to determine size and strategy
      final fileInfo = await _api.getFileInfo(fileId);
      final fileSize = fileInfo['size'] as int? ?? 0;
      
      debugPrint('[FILE_TRANSFER] File size: $fileSize bytes');
      
       // CRITICAL FIX: Ensure directory exists with proper error handling
       final directory = File(actualSavePath).parent;
       try {
         if (!await directory.exists()) {
           debugPrint('[FILE_TRANSFER] Creating directory: ${directory.path}');
           await directory.create(recursive: true);
         }
         
         // Verify directory is writable
         if (!await directory.exists()) {
           throw Exception('Failed to create download directory: ${directory.path}');
         }
         
         debugPrint('[FILE_TRANSFER] Directory ready: ${directory.path}');
       } catch (e) {
         debugPrint('[FILE_TRANSFER] Directory setup failed: $e');
         throw Exception('Cannot setup download directory: $e');
       }
      
      // Use chunked download for large files (>100MB)
      if (fileSize > 100 * 1024 * 1024) {
        debugPrint('[FILE_TRANSFER] Using chunked download for large file: $fileSize bytes');
        
        // Update transfer with actual file size
        final transferIndex = _transfers.indexWhere((t) => t.id == fileId);
        if (transferIndex >= 0) {
          _transfers[transferIndex] = _transfers[transferIndex].copyWith(fileSize: fileSize);
        }
        
        int lastReportedProgress = 0;
        await _api.downloadLargeFileToPath(
          fileId: fileId,
          savePath: actualSavePath,
          onReceiveProgress: (received, total) {
            // Only update progress on significant changes to avoid too many UI updates
            if (total > 0 && (received - lastReportedProgress) >= (total ~/ 100)) {  // Update every 1%
              final progress = received / total;
              _updateProgress(fileId, progress, (p) {});  // Update internal progress without duplicating callback
              onProgress(progress);
              lastReportedProgress = received;
            }
          },
        );
      } else {
        debugPrint('[FILE_TRANSFER] Using regular download for small file: $fileSize bytes');
        
        // Update transfer with actual file size and track progress
        final transferIndex = _transfers.indexWhere((t) => t.id == fileId);
        if (transferIndex >= 0) {
          _transfers[transferIndex] = _transfers[transferIndex].copyWith(fileSize: fileSize);
        }
        
        await _api.downloadFileToPathWithProgress(
          fileId: fileId,
          savePath: actualSavePath,
          onProgress: (progress) {
            // Track progress for small files too
            _updateProgress(fileId, progress, onProgress);
            onProgress(progress);
          },
        );
      }
      
      _markCompleted(fileId);
      onProgress(1);
      
      // Verify file was downloaded successfully
      final file = File(actualSavePath);
      if (!await file.exists()) {
        throw Exception('File download completed but file not found at path: $actualSavePath');
      }
      
      debugPrint('[FILE_TRANSFER] Download completed successfully: $actualSavePath');
    } catch (e) {
      debugPrint('[FILE_TRANSFER] Download failed: $e');
      _markFailed(fileId);
      rethrow;
    }
  }

  Future<void> cancelTransfer(String transferId) async {
    try {
      final index = _transfers.indexWhere((t) => t.id == transferId);
      if (index != -1) {
        _transfers[index] = _transfers[index].copyWith(
          status: TransferStatus.cancelled,
        );
        _transfers.removeAt(index);
      }
    } catch (e) {
      rethrow;
    }
  }

  FileTransfer? getTransfer(String transferId) {
    try {
      return _transfers.firstWhere((t) => t.id == transferId);
    } catch (e) {
      return null;
    }
  }

  void clearCompleted() {
    _transfers.removeWhere((t) => t.status == TransferStatus.completed);
  }

  void clearAll() {
    _transfers.clear();
  }

  void _updateProgress(String transferId, double p, Function(double) onProgress) {
    final index = _transfers.indexWhere((t) => t.id == transferId);
    if (index != -1) {
      final clamped = p.clamp(0.0, 1.0);
      // Update internal state first
      _transfers[index] = _transfers[index].copyWith(progress: clamped);
      // Then call external callback with consistent value
      onProgress(clamped);
    }
  }

  // Sanitize file name to prevent directory traversal and invalid characters
  String _sanitizeFileName(String fileName) {
    // Remove path traversal attempts
    String sanitized = fileName
        .replaceAll(RegExp(r'\.\.[\\/]'), '') // Remove ../
        .replaceAll(RegExp(r'^[\\/]'), '') // Remove leading /
        .replaceAll(RegExp(r'[<>:"|?*]'), '_') // Replace invalid characters
        .trim();
    
    // Ensure filename is not empty
    if (sanitized.isEmpty) {
      sanitized = 'download_${DateTime.now().millisecondsSinceEpoch}';
    }
    
    // Limit filename length
    if (sanitized.length > 255) {
      final extension = sanitized.contains('.') ? 
          sanitized.substring(sanitized.lastIndexOf('.')) : '';
      final nameWithoutExt = sanitized.contains('.') ? 
          sanitized.substring(0, sanitized.lastIndexOf('.')) : sanitized;
      sanitized = '${nameWithoutExt.substring(0, 255 - extension.length)}$extension';
    }
    
    return sanitized;
  }

  void _markCompleted(String transferId) {
    final index = _transfers.indexWhere((t) => t.id == transferId);
    if (index != -1) {
      _transfers[index] = _transfers[index].copyWith(status: TransferStatus.completed, progress: 1);
    }
  }

  void _markFailed(String transferId) {
    final index = _transfers.indexWhere((t) => t.id == transferId);
    if (index != -1) {
      _transfers[index] = _transfers[index].copyWith(status: TransferStatus.failed);
    }
  }
}

enum TransferStatus { uploading, downloading, completed, failed, cancelled }

enum TransferDirection { upload, download }

class FileTransfer {
  final String id;
  final String fileName;
  final int fileSize;
  final String filePath;
  final String chatId;
  final TransferStatus status;
  final TransferDirection direction;
  final double progress;

  FileTransfer({
    required this.id,
    required this.fileName,
    required this.fileSize,
    required this.filePath,
    required this.chatId,
    required this.status,
    required this.direction,
    required this.progress,
  });

  FileTransfer copyWith({
    String? id,
    String? fileName,
    int? fileSize,
    String? filePath,
    String? chatId,
    TransferStatus? status,
    TransferDirection? direction,
    double? progress,
  }) {
    return FileTransfer(
      id: id ?? this.id,
      fileName: fileName ?? this.fileName,
      fileSize: fileSize ?? this.fileSize,
      filePath: filePath ?? this.filePath,
      chatId: chatId ?? this.chatId,
      status: status ?? this.status,
      direction: direction ?? this.direction,
      progress: progress ?? this.progress,
    );
  }
}
