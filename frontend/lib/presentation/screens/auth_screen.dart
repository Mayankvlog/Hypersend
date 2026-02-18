import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:go_router/go_router.dart';
import 'package:dio/dio.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/service_provider.dart';
import '../../data/services/api_service.dart';
import '../../data/models/user.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  bool _isLogin = true;
  bool _loading = false;
  bool _obscurePassword = true;

  final _name = TextEditingController();
  final _email = TextEditingController();
  final _password = TextEditingController();

  @override
  void dispose() {
    _name.dispose();
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    final email = _email.text.trim();
    final password = _password.text;
    final name = _name.text.trim();
    
    // Operator precedence: explicitly check each condition
    final isEmailEmpty = email.isEmpty;
    final isPasswordEmpty = password.isEmpty;
    final isNameRequired = !_isLogin && name.isEmpty;
    
    if (isEmailEmpty || isPasswordEmpty || isNameRequired) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please fill all required fields')),
      );
      return;
    }

    setState(() => _loading = true);
    
    try {
      // Check server connectivity first
      final isServerConnected = await serviceProvider.apiService.checkServerConnectivity();
      if (!isServerConnected) {
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              '🚫 Server is not accessible. This could be due to:\n'
              '• Server is down for maintenance\n'
              '• Network connectivity issues\n'
              '• DNS resolution problems\n\n'
              'Please try again in a few minutes.',
            ),
            backgroundColor: AppTheme.errorRed,
            duration: const Duration(seconds: 8),
            action: SnackBarAction(
              label: 'Retry',
              textColor: Colors.white,
              onPressed: () => _submit(),
            ),
          ),
        );
        return;
      }
      
      if (_isLogin) {
        await serviceProvider.authService.login(email: email, password: password);
      } else {
        await serviceProvider.authService.registerAndLogin(name: name, email: email, password: password);
      }

      // After successful auth, fetch current user and populate profile service
      try {
        final me = await serviceProvider.apiService.getMe();
        serviceProvider.profileService.setUser(User.fromApi(me));
      } catch (e) {
        // ignore - navigation will continue but profile-dependent features may request login again
      }

      if (!mounted) return;
      context.go('/chats');
    } catch (e) {
      if (!mounted) return;
      
      String errorMessage = 'Authentication failed';
      
      if (e is DioException) {
        errorMessage = ApiService.getErrorMessage(e);
      } else {
        final errorStr = e.toString().toLowerCase();
        if (errorStr.contains('connection') || errorStr.contains('network')) {
          errorMessage = '🌐 Cannot connect to server. Please check your internet connection and try again.';
        } else if (errorStr.contains('invalid') || errorStr.contains('unauthorized')) {
          errorMessage = '🔐 Invalid email or password. Please check your credentials.';
        } else if (errorStr.contains('timeout')) {
          errorMessage = '⏰ Request timed out. Please try again.';
        } else if (errorStr.contains('server')) {
          errorMessage = '🖥️ Server error. Please try again later.';
        }
      }
      
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(errorMessage),
          backgroundColor: AppTheme.errorRed,
          duration: const Duration(seconds: 4),
        ),
      );
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(AppTheme.spacing24),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const SizedBox(height: 24),
              Text(
                'zaply',
                style: Theme.of(context).textTheme.headlineLarge?.copyWith(fontWeight: FontWeight.w800),
              ),
              const SizedBox(height: 6),
              Text(
                _isLogin ? 'Login to continue' : 'Create your account',
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: AppTheme.textSecondary),
              ),
              const SizedBox(height: 32),
              if (!_isLogin) ...[
                TextField(
                  controller: _name,
                  decoration: const InputDecoration(
                    labelText: 'Name',
                    prefixIcon: Icon(Icons.person_outline),
                  ),
                ),
                const SizedBox(height: 16),
              ],
              TextField(
                controller: _email,
                keyboardType: TextInputType.emailAddress,
                decoration: const InputDecoration(
                  labelText: 'Email',
                  prefixIcon: Icon(Icons.mail_outline),
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _password,
                obscureText: _obscurePassword,
                decoration: InputDecoration(
                  labelText: 'Password',
                  prefixIcon: const Icon(Icons.lock_outline),
                  suffixIcon: IconButton(
                    icon: Icon(_obscurePassword ? Icons.visibility_off : Icons.visibility),
                    onPressed: () {
                      setState(() {
                        _obscurePassword = !_obscurePassword;
                      });
                    },
                  ),
                ),
              ),
              const SizedBox(height: 24),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: _loading ? null : _submit,
                  child: Text(_loading ? 'Please wait…' : (_isLogin ? 'Login' : 'Register')),
                ),
              ),
              const SizedBox(height: 12),
              if (_isLogin)
                Align(
                  alignment: Alignment.centerLeft,
                  child: TextButton(
                    onPressed: _loading
                        ? null
                        : () async {
                            // Combined "Forgot password" + "Reset with token" flow
                            final emailController = TextEditingController(text: _email.text.trim());
                            final tokenController = TextEditingController();
                            final newPasswordController = TextEditingController();

                            final confirmed = await showDialog<bool>(
                              context: context,
                              builder: (context) {
                                return AlertDialog(
                                  title: const Text('Forgot Password'),
                                  content: SingleChildScrollView(
                                    child: Column(
                                      mainAxisSize: MainAxisSize.min,
                                      children: [
                                        const Text('1. Enter your email and tap "Send Token" to receive a reset code.'),
                                        const SizedBox(height: 8),
                                        const Text('2. Paste the token and choose a new password, then tap "Reset Password".'),
                                        const SizedBox(height: 16),
                                        TextField(
                                          controller: emailController,
                                          keyboardType: TextInputType.emailAddress,
                                          decoration: const InputDecoration(
                                            labelText: 'Email',
                                            prefixIcon: Icon(Icons.email_outlined),
                                          ),
                                        ),
                                        const SizedBox(height: 12),
                                        TextField(
                                          controller: tokenController,
                                          decoration: const InputDecoration(
                                            labelText: 'Reset token',
                                            prefixIcon: Icon(Icons.key_outlined),
                                          ),
                                        ),
                                        const SizedBox(height: 12),
                                        TextField(
                                          controller: newPasswordController,
                                          obscureText: true,
                                          decoration: const InputDecoration(
                                            labelText: 'New password',
                                            prefixIcon: Icon(Icons.lock_reset_outlined),
                                          ),
                                        ),
                                      ],
                                    ),
                                  ),
                                  actions: [
                                    TextButton(
                                      onPressed: () => Navigator.of(context).pop(false),
                                      child: const Text('Close'),
                                    ),
                                    TextButton(
                                      onPressed: () async {
                                        final email = emailController.text.trim();
                                        if (email.isEmpty) {
                                          ScaffoldMessenger.of(context).showSnackBar(
                                            const SnackBar(content: Text('Enter email to send reset token')),
                                          );
                                          return;
                                        }

                                        // Send reset token
                                        try {
                                          final response = await serviceProvider.authService.requestPasswordReset(email);

                                          // Extract token from response if backend returns it (dev/debug mode)
                                          final String? token = response['token'] as String?;
                                          if (token != null && token.isNotEmpty) {
                                            tokenController.text = token;
                                            await Clipboard.setData(ClipboardData(text: token));
                                            if (mounted) {
                                              ScaffoldMessenger.of(context).showSnackBar(
                                                const SnackBar(
                                                  content: Text('Token copied to clipboard (dev mode)'),
                                                  backgroundColor: AppTheme.successGreen,
                                                ),
                                              );
                                            }
                                          } else {
                                            if (mounted) {
                                              ScaffoldMessenger.of(context).showSnackBar(
                                                const SnackBar(
                                                  content: Text('Check your email for password reset instructions'),
                                                  backgroundColor: AppTheme.successGreen,
                                                ),
                                              );
                                            }
                                          }
                                        } catch (e) {
                                          if (!mounted) return;
                                          String error = 'Failed to request password reset';
                                          if (e is DioException) {
                                            error = ApiService.getErrorMessage(e);
                                          }
                                          ScaffoldMessenger.of(context).showSnackBar(
                                            SnackBar(
                                              content: Text(error),
                                              backgroundColor: AppTheme.errorRed,
                                            ),
                                          );
                                        }
                                      },
                                      child: const Text('Send Token'),
                                    ),
                                    ElevatedButton(
                                      onPressed: () async {
                                        final email = emailController.text.trim();
                                        final token = tokenController.text.trim();
                                        final newPassword = newPasswordController.text;

                                        if (email.isEmpty || token.isEmpty || newPassword.isEmpty) {
                                          ScaffoldMessenger.of(context).showSnackBar(
                                            const SnackBar(
                                              content: Text('Enter email, reset token and new password'),
                                            ),
                                          );
                                          return;
                                        }

                                        try {
                                          await serviceProvider.authService.resetPasswordWithToken(
                                            token: token,
                                            newPassword: newPassword,
                                          );
                                          if (!mounted) return;
                                          Navigator.of(context).pop(true);
                                          ScaffoldMessenger.of(context).showSnackBar(
                                            const SnackBar(
                                              content: Text('Password reset successfully.'),
                                              backgroundColor: AppTheme.successGreen,
                                            ),
                                          );
                                        } catch (e) {
                                          if (!mounted) return;
                                          String error = 'Failed to reset password';
                                          if (e is DioException) {
                                            error = ApiService.getErrorMessage(e);
                                          }
                                          ScaffoldMessenger.of(context).showSnackBar(
                                            SnackBar(
                                              content: Text(error),
                                              backgroundColor: AppTheme.errorRed,
                                            ),
                                          );
                                        }
                                      },
                                      child: const Text('Reset Password'),
                                    ),
                                  ],
                                );
                              },
                            );

                            emailController.dispose();
                            tokenController.dispose();
                            newPasswordController.dispose();

                            // confirmed is only used to close the dialog; no extra handling needed here
                            if (confirmed != true) {
                              return;
                            }
                          },
                    child: const Text('Forgot Password?'),
                  ),
                ),
              TextButton(
                onPressed: _loading
                    ? null
                    : () {
                        setState(() => _isLogin = !_isLogin);
                      },
                child: Text(_isLogin ? 'Create an account' : 'I already have an account'),
              ),
              const Spacer(),
              // Backend URL text removed for security / privacy; keep UI clean in production.
            ],
          ),
        ),
      ),
    );
  }
}


