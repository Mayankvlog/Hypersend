import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';
import '../../core/theme/app_theme.dart';
import '../../data/services/service_provider.dart';
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
    if (email.isEmpty || password.isEmpty || (!_isLogin && name.isEmpty)) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Please fill all required fields')),
      );
      return;
    }

    setState(() => _loading = true);
    try {
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
          errorMessage = '🌐 Cannot connect to server. Please check your internet.';
        } else if (errorStr.contains('invalid') || errorStr.contains('unauthorized')) {
          errorMessage = 'Invalid email or password';
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
                'Zaply',
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
                  alignment: Alignment.centerRight,
                  child: TextButton(
                    onPressed: _loading
                        ? null
                        : () async {
                            final email = _email.text.trim();
                            if (email.isEmpty) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: Text('Enter your email first to reset password')),
                              );
                              return;
                            }
                            
                            setState(() => _loading = true);
                            try {
                              await serviceProvider.authService.resetPassword(email: email);
                              if (!mounted) return;
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(
                                  content: Text('Password reset link has been sent to your email.'),
                                  backgroundColor: AppTheme.successGreen,
                                ),
                              );
                            } catch (e) {
                              if (!mounted) return;
                              String error = 'Failed to send reset link';
                              if (e is DioException) {
                                error = ApiService.getErrorMessage(e);
                              }
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(
                                  content: Text(error),
                                  backgroundColor: AppTheme.errorRed,
                                ),
                              );
                            } finally {
                              if (mounted) setState(() => _loading = false);
                            }
                          },
                    child: const Text('Forgot password?'),
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


