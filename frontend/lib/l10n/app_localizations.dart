import 'package:flutter/material.dart';

class _AppLocalizationsDelegate extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  bool isSupported(Locale locale) {
    return AppLocalizations.supportedLocales
        .any((supportedLocale) => supportedLocale.languageCode == locale.languageCode);
  }

  @override
  Future<AppLocalizations> load(Locale locale) async {
    return AppLocalizations();
  }

  @override
  bool shouldReload(LocalizationsDelegate<AppLocalizations> old) => false;
}

class AppLocalizations {
  static const List<Locale> supportedLocales = [
    Locale('en', 'US'), // English
    Locale('es', 'ES'), // Spanish
    Locale('fr', 'FR'), // French
    Locale('de', 'DE'), // German
    Locale('hi', 'IN'), // Hindi
    Locale('ar', 'SA'), // Arabic (RTL)
  ];

  static const Locale fallbackLocale = Locale('en', 'US');

  static bool isRTL(Locale locale) {
    return locale.languageCode == 'ar';
  }

  // Basic strings - can be expanded
  static String get appName => 'Zaply';
  static String get chats => 'Chats';
  static String get settings => 'Settings';
  static String get messages => 'Messages';
  static String get send => 'Send';
  static String get cancel => 'Cancel';
  static String get ok => 'OK';
  static String get error => 'Error';
  static String get loading => 'Loading...';
  static String get retry => 'Retry';
  static String get search => 'Search';
  static String get transfer => 'Transfer';
  static String get fileTransfer => 'File Transfer';
  static String get selectFile => 'Select File';
  static String get uploading => 'Uploading...';
  static String get downloading => 'Downloading...';
  static String get completed => 'Completed';
  static String get failed => 'Failed';
  static String get paused => 'Paused';
  static String get resume => 'Resume';
  static String get newContact => 'New Contact';
  static String get addContact => 'Add Contact';
  static String get email => 'Email';
  static String get username => 'Username';
  static String get password => 'Password';
  static String get login => 'Login';
  static String get logout => 'Logout';
  static String get register => 'Register';
  static String get forgotPassword => 'Forgot Password?';
  static String get savedMessages => 'Saved Messages';
  static String get online => 'Online';
  static String get offline => 'Offline';
  static String get typing => 'typing...';
  static String get connectionLost => 'Connection Lost';
  static String get reconnecting => 'Reconnecting...';
  static String get noInternet => 'No Internet Connection';
  static String get serverError => 'Server Error';
  static String get somethingWentWrong => 'Something went wrong';
  static String get pleaseTryAgain => 'Please try again';

  static const LocalizationsDelegate<AppLocalizations> delegate = _AppLocalizationsDelegate();

  static AppLocalizations of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations) ?? AppLocalizations();
  }
}