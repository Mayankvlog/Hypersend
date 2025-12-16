import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/file_transfer_service.dart';
import '../../data/services/service_provider.dart';

class FileTransferScreen extends StatefulWidget {
  const FileTransferScreen({super.key});

  @override
  State<FileTransferScreen> createState() => _FileTransferScreenState();
}

class _FileTransferScreenState extends State<FileTransferScreen> {
  late FileTransferService _fileTransferService;

  @override
  void initState() {
    super.initState();
    _fileTransferService = serviceProvider.fileTransferService;
  }

  Future<void> _uploadFile() async {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('File upload feature coming soon')),
    );
  }

  Future<void> _downloadFile() async {
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('File download feature coming soon')),
    );
  }

  String _formatFileSize(int bytes) {
    if (bytes == 0) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB'];
    final i = (bytes.toString().length / 3).floor();
    return '${(bytes / (1 << (i * 10))).toStringAsFixed(2)} ${sizes[i]}';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.arrow_back),
          onPressed: () => context.pop(),
        ),
        title: const Text('File Transfer'),
      ),
      body: Column(
        children: [
          // Active transfers section
          Expanded(
            child: _fileTransferService.activeTransfers.isEmpty
                ? Center(
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Icon(
                          Icons.cloud_upload_outlined,
                          size: 64,
                          color: AppTheme.textSecondary,
                        ),
                        const SizedBox(height: 16),
                        Text(
                          'No active transfers',
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                        const SizedBox(height: 8),
                        Text(
                          'Upload or download files to get started',
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  )
                : ListView.builder(
                    itemCount:
                        _fileTransferService.activeTransfers.length,
                    itemBuilder: (context, index) {
                      final transfer =
                          _fileTransferService.activeTransfers[index];
                      return _buildTransferTile(transfer);
                    },
                  ),
          ),
        ],
      ),
      floatingActionButton: Column(
        mainAxisAlignment: MainAxisAlignment.end,
        children: [
          FloatingActionButton(
            heroTag: 'download',
            onPressed: _downloadFile,
            tooltip: 'Download File',
            child: const Icon(Icons.download),
          ),
          const SizedBox(height: 16),
          FloatingActionButton(
            heroTag: 'upload',
            onPressed: _uploadFile,
            tooltip: 'Upload File',
            child: const Icon(Icons.upload),
          ),
        ],
      ),
    );
  }

  Widget _buildTransferTile(FileTransfer transfer) {
    final isUpload = transfer.direction == TransferDirection.upload;
    final isCompleted = transfer.status == TransferStatus.completed;
    final isFailed = transfer.status == TransferStatus.failed;

    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Container(
        decoration: BoxDecoration(
          color: AppTheme.cardDark,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // File info
              Row(
                children: [
                  Icon(
                    isUpload ? Icons.upload : Icons.download,
                    color: AppTheme.primaryCyan,
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          transfer.fileName,
                          style: const TextStyle(
                            fontWeight: FontWeight.w600,
                            fontSize: 14,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          _formatFileSize(transfer.fileSize),
                          style: Theme.of(context).textTheme.bodySmall,
                        ),
                      ],
                    ),
                  ),
                  if (!isCompleted && !isFailed)
                    IconButton(
                      icon: const Icon(Icons.close, size: 18),
                      onPressed: () async {
                        await serviceProvider.fileTransferService
                            .cancelTransfer(transfer.id);
                        setState(() {});
                      },
                      color: AppTheme.textSecondary,
                      iconSize: 18,
                      padding: EdgeInsets.zero,
                    ),
                ],
              ),
              const SizedBox(height: 12),
              // Progress bar
              if (!isCompleted && !isFailed)
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    ClipRRect(
                      borderRadius: BorderRadius.circular(4),
                      child: LinearProgressIndicator(
                        value: transfer.progress,
                        minHeight: 6,
                        backgroundColor: AppTheme.backgroundDark,
                        valueColor: const AlwaysStoppedAnimation<Color>(
                          AppTheme.primaryCyan,
                        ),
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      '${(transfer.progress * 100).toStringAsFixed(0)}%',
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                  ],
                ),
              if (isCompleted)
                Row(
                  children: [
                    const Icon(
                      Icons.check_circle,
                      color: AppTheme.successGreen,
                      size: 18,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      'Completed',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: AppTheme.successGreen,
                          ),
                    ),
                  ],
                ),
              if (isFailed)
                Row(
                  children: [
                    const Icon(
                      Icons.error,
                      color: AppTheme.errorRed,
                      size: 18,
                    ),
                    const SizedBox(width: 8),
                    Text(
                      'Failed',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: AppTheme.errorRed,
                          ),
                    ),
                  ],
                ),
            ],
          ),
        ),
      ),
    );
  }
}
