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

  /// Pick and upload a file using the backend's resumable chunk upload API.
  /// This supports very large files (e.g. 40GB) on desktop/mobile where `dart:io` is available.
  Future<void> pickAndUpload({
    required String chatId,
    required Function(double) onProgress,
  }) async {
    final result = await FilePicker.platform.pickFiles(
      withReadStream: true,
      type: FileType.any, // Allow all file types
      allowMultiple: false,
    );
    if (result == null || result.files.isEmpty) return;

    final file = result.files.single;
    if (file.name.isEmpty || file.size <= 0) {
      throw Exception('Invalid file selection');
    }

    // Check against 40GB limit
    if (file.size > ApiConstants.maxFileSizeBytes) {
      final sizeGB = file.size / (1024 * 1024 * 1024);
      throw Exception('File size (${sizeGB.toStringAsFixed(2)}GB) exceeds 40GB limit');
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
      final init = await _api.initUpload(
        filename: fileName,
        size: fileSize,
        mime: mime,  // API service converts this to mime_type
        chatId: chatId,
      );

      final uploadId = (init['uploadId'] ?? init['upload_id']) as String;  // Support both camelCase and snake_case
      final chunkSize = (init['chunk_size'] as num).toInt();
      final totalChunks = (init['total_chunks'] as num?)?.toInt();  // Get total_chunks from backend for validation

      int chunkIndex = 0;
      int sentBytes = 0;
      final buffer = BytesBuilder(copy: false);

      await for (final part in stream) {
        buffer.add(part);
        while (buffer.length >= chunkSize) {
          final bytes = buffer.takeBytes();
          final chunk = bytes.sublist(0, chunkSize);
          final remaining = bytes.sublist(chunkSize);
          if (remaining.isNotEmpty) buffer.add(remaining);

          final checksum = sha256.convert(chunk).toString();
          try {
            // CRITICAL FIX: Validate chunk index against backend total_chunks to prevent out-of-range errors
            if (totalChunks != null && chunkIndex >= totalChunks) {
              throw Exception(
                'Chunk index $chunkIndex out of range. Expected: 0-${totalChunks - 1}. '
                'This indicates a calculation mismatch between frontend and backend.'
              );
            }
            
            await _api.uploadChunk(
              uploadId: uploadId,
              chunkIndex: chunkIndex,
              bytes: Uint8List.fromList(chunk),
              chunkChecksum: checksum,
            );
            debugPrint('[TRANSFER] Chunk $chunkIndex uploaded successfully (${chunk.length} bytes)');
            chunkIndex += 1;
            sentBytes += chunk.length;
          } catch (e) {
            debugPrint('[TRANSFER] Failed to upload chunk $chunkIndex: $e');
            // Check if it's a validation error (400)
            if (e.toString().contains('400') || e.toString().contains('Bad Request')) {
              debugPrint('[TRANSFER] This might be a server configuration issue. Check:');
              debugPrint('[TRANSFER] 1. Upload ID is valid and not expired');
              debugPrint('[TRANSFER] 2. Chunk index is within valid range');
              debugPrint('[TRANSFER] 3. File size is within limits');
              debugPrint('[TRANSFER] 4. Content type is application/octet-stream');
            }
            rethrow;
          }
// Prevent double callback invocation
          final progress = sentBytes / fileSize;
          _updateProgress(transfer.id, progress, (_) {}); // Internal update only
        }
      }

      final tail = buffer.takeBytes();
      if (tail.isNotEmpty) {
        // CRITICAL FIX: Validate final chunk index against backend total_chunks
        if (totalChunks != null && chunkIndex >= totalChunks) {
          throw Exception(
            'Final chunk index $chunkIndex out of range. Expected: 0-${totalChunks - 1}. '
            'This indicates a calculation mismatch between frontend and backend.'
          );
        }
        
        final checksum = sha256.convert(tail).toString();
        await _api.uploadChunk(
          uploadId: uploadId,
          chunkIndex: chunkIndex,
          bytes: Uint8List.fromList(tail),
          chunkChecksum: checksum,
        );
        sentBytes += tail.length;
        _updateProgress(transfer.id, sentBytes / fileSize, onProgress);
      }

      await _api.completeUpload(uploadId: uploadId);
      _markCompleted(transfer.id);
    } catch (e) {
      _markFailed(transfer.id);
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
    // Generate proper download path
    String actualSavePath;
    if (kIsWeb) {
      throw Exception('File download not supported on web platform');
    } else {
      // For native platforms, get downloads directory
      Directory? directory;
      try {
        directory = await getDownloadsDirectory();
      } catch (e) {
        debugPrint('[FILE_TRANSFER] Could not get downloads directory: $e');
      }
      
      directory ??= await getApplicationDocumentsDirectory();
      actualSavePath = '${directory.path}/$savePath';
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
      
      // Ensure directory exists
      final directory = File(actualSavePath).parent;
      if (!await directory.exists()) {
        await directory.create(recursive: true);
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
