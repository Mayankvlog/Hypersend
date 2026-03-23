import 'dart:typed_data';
import 'dart:async';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart' show debugPrint, kIsWeb;
import 'package:path_provider/path_provider.dart';
import 'package:http/http.dart' as http;
import 'api_service.dart';
import '../../core/constants/api_constants.dart';

// Conditional imports for platform-specific implementations
import 'file_transfer_io.dart' if (dart.library.html) 'file_transfer_io_stub.dart' as io;

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
      id: DateTime.now().toUtc().millisecondsSinceEpoch.toString(),
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
      if (kIsWeb) {
        // For web, use http package instead of HttpClient
        final response = await http.put(
          Uri.parse(uploadUrl),
          body: fileBytes,
          headers: {'Content-Type': mime},
        );
        
        if (response.statusCode != 200 && response.statusCode != 204) {
          throw Exception('S3 upload failed: ${response.statusCode}');
        }
      } else {
        // For native platforms, use HttpClient
        final client = io.HttpClient();
        try {
          final request = await client.putUrl(Uri.parse(uploadUrl));
          request.headers.set('content-type', mime);
          request.add(fileBytes);
          
          // Upload to S3
          final response = await request.close();
          
          // Check response status code
          if (response.statusCode != 200 && response.statusCode != 204) {
            throw Exception('S3 upload failed: ${response.statusCode}');
          }
        } finally {
          client.close();
        }
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

  /// Download file to a local path (desktop/mobile only).
  /// On web platform, this throws an exception as downloads are handled differently.
  Future<void> downloadFile({
    required String fileId,
    required String fileName,
    required String savePath,
    required Function(double) onProgress,
  }) async {
    // Web platform doesn't support direct file downloads to filesystem
    if (kIsWeb) {
      throw UnsupportedError('File download to local filesystem is not supported on web platform. Use browser download instead.');
    }

    String actualSavePath;
    try {
      if (savePath.isEmpty) {
        final directory = await getApplicationDocumentsDirectory();
        actualSavePath = '${directory.path}/$fileName';
      } else {
        actualSavePath = savePath;
      }
      
      // Ensure parent directory exists
      final file = io.File(actualSavePath);
      final parentDir = file.parent;
      if (!await parentDir.exists()) {
        await parentDir.create(recursive: true);
      }
    } catch (e) {
      debugPrint('[FILE_TRANSFER] Error preparing download path: $e');
      throw Exception('Unable to prepare save location for downloaded file');
    }

    try {
      // Create transfer record with proper file ID and metadata
      final transfer = FileTransfer(
        id: fileId,
        fileName: fileName,
        filePath: actualSavePath,
        fileSize: 0, // Will be updated after getting file info
        status: TransferStatus.downloading,
        progress: 0.0,
        direction: TransferDirection.download,
        chatId: '', // Not used for downloads
      );
      
      _transfers.add(transfer);
      debugPrint('[FILE_TRANSFER] Download started: $fileId -> $actualSavePath');
      
      // Get file info first for size validation and proper filename
      try {
        final fileInfo = await _api.getFileInfo(fileId);
        final fileSize = fileInfo['size'] as int? ?? 0;
        final originalFilename = fileInfo['filename']?.toString() ?? fileName;
        
        // CRITICAL FIX: Ensure save path uses correct filename with extension
        if (originalFilename != fileName) {
          // Update save path with correct filename
          final file = io.File(actualSavePath);
          final parentDir = file.parent;
          actualSavePath = '${parentDir.path}/$originalFilename';
          debugPrint('[FILE_TRANSFER] Updated filename: $fileName -> $originalFilename');
        }
        
        // Update transfer with actual file size and correct filename
        final transferIndex = _transfers.indexWhere((t) => t.id == fileId);
        if (transferIndex >= 0) {
          _transfers[transferIndex] = _transfers[transferIndex].copyWith(
            fileSize: fileSize,
            fileName: originalFilename,
            filePath: actualSavePath,
          );
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
      } catch (e) {
        debugPrint('[FILE_TRANSFER] Error getting file info: $e');
        // Continue with download without size info
        await _api.downloadFileToPathWithProgress(
          fileId: fileId,
          savePath: actualSavePath,
          onProgress: (progress) {
            // Update transfer progress
            final transferIndex = _transfers.indexWhere((t) => t.id == fileId);
            if (transferIndex >= 0) {
              _transfers[transferIndex] = _transfers[transferIndex].copyWith(
                progress: progress,
                status: progress >= 1.0 ? TransferStatus.completed : TransferStatus.downloading,
              );
            }
            
            onProgress(progress);
          },
        );
      }
      
      _markCompleted(fileId);
      onProgress(1);
      
      // Verify file was downloaded successfully (native only)
      if (!kIsWeb) {
        final file = io.File(actualSavePath);
        if (!await file.exists()) {
          throw Exception('File download completed but file not found at path: $actualSavePath');
        }
        
        debugPrint('[FILE_TRANSFER] Download completed successfully: $actualSavePath');
      }
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
