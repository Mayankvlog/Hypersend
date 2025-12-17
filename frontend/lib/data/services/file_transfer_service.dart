import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'package:file_picker/file_picker.dart';
import 'api_service.dart';

class FileTransferService {
  final ApiService _api;
  final List<FileTransfer> _transfers = [];

  FileTransferService(this._api);

  List<FileTransfer> get activeTransfers => _transfers;

  /// Pick and upload a file using the backend's resumable chunk upload API.
  /// This supports very large files (e.g. 40GB) on desktop/mobile where `dart:io` is available.
  Future<void> pickAndUpload({
    required String chatId,
    required Function(double) onProgress,
  }) async {
    final result = await FilePicker.platform.pickFiles(withReadStream: true);
    if (result == null || result.files.isEmpty) return;

    final file = result.files.single;
    if (file.name.isEmpty || file.size <= 0) {
      throw Exception('Invalid file selection');
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
        mime: mime,
        chatId: chatId,
      );

      final uploadId = init['upload_id'] as String;
      final chunkSize = (init['chunk_size'] as num).toInt();

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
          await _api.uploadChunk(
            uploadId: uploadId,
            chunkIndex: chunkIndex,
            bytes: Uint8List.fromList(chunk),
            chunkChecksum: checksum,
          );
          chunkIndex += 1;
          sentBytes += chunk.length;
          _updateProgress(transfer.id, sentBytes / fileSize, onProgress);
        }
      }

      final tail = buffer.takeBytes();
      if (tail.isNotEmpty) {
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
    final transfer = FileTransfer(
      id: fileId,
      fileName: fileName,
      fileSize: 0,
      filePath: savePath,
      chatId: '',
      status: TransferStatus.downloading,
      direction: TransferDirection.download,
      progress: 0,
    );
    _transfers.add(transfer);

    try {
      await _api.downloadFileToPath(fileId: fileId, savePath: savePath);
      _markCompleted(fileId);
      onProgress(1);
    } catch (e) {
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
      _transfers[index] = _transfers[index].copyWith(progress: clamped);
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
