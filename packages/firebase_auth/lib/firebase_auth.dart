// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:meta/meta.dart';

/// Represents user data returned from an identity provider.
class UserInfo {
  final Map<dynamic, dynamic> _data;

  UserInfo._(this._data);

  /// The provider identifier.
  String get providerId => _data['providerId'];

  /// The provider’s user ID for the user.
  String get uid => _data['uid'];

  /// The name of the user.
  String get displayName => _data['displayName'];

  /// The URL of the user’s profile photo.
  String get photoUrl => _data['photoUrl'];

  /// The user’s email address.
  String get email => _data['email'];

  /// The user's phone number.
  String get phoneNumber => _data['phoneNumber'];

  @override
  String toString() {
    return '$runtimeType($_data)';
  }
}

/// Represents user profile data that can be updated by [updateProfile]
///
/// The purpose of having separate class with a map is to give possibility
/// to check if value was set to null or not provided
class UserUpdateInfo {
  /// Container of data that will be send in update request
  final Map<String, String> _updateData = <String, String>{};

  set displayName(String displayName) =>
      _updateData["displayName"] = displayName;

  String get displayName => _updateData["displayName"];

  set photoUrl(String photoUri) => _updateData["photoUrl"] = photoUri;

  String get photoUrl => _updateData["photoUrl"];
}

/// Represents a user.
class FirebaseUser extends UserInfo {
  final List<UserInfo> providerData;

  FirebaseUser._(Map<dynamic, dynamic> data)
      : providerData = data['providerData']
            .map<UserInfo>((dynamic item) => new UserInfo._(item))
            .toList(),
        super._(data);

  // Returns true if the user is anonymous; that is, the user account was
  // created with signInAnonymously() and has not been linked to another
  // account.
  bool get isAnonymous => _data['isAnonymous'];

  /// Returns true if the user's email is verified.
  bool get isEmailVerified => _data['isEmailVerified'];

  /// Obtains the id token for the current user, forcing a [refresh] if desired.
  ///
  /// Useful when authenticating against your own backend. Use our server
  /// SDKs or follow the official documentation to securely verify the
  /// integrity and validity of this token.
  ///
  /// Completes with an error if the user is signed out.
  ///
  Future<String> getIdToken({bool refresh = false}) async {
    return await FirebaseAuth.channel.invokeMethod('getIdToken', <String, bool>{
      'refresh': refresh,
    });
  }

  /// Initiates email verification for the user.
  ///
  Future<void> sendEmailVerification() async {
    await FirebaseAuth.channel.invokeMethod('sendEmailVerification');
  }

  /// Manually refreshes the data of the current user (for example,
  /// attached providers, display name, and so on).
  ///
  Future<void> reload() async {
    await FirebaseAuth.channel.invokeMethod('reload');
  }

  /// Deletes the user record from your Firebase project's database.
  ///
  Future<void> delete() async {
    await FirebaseAuth.channel.invokeMethod('delete');
  }

  /// Updates the email address of the user.
  ///
  /// The original email address recipient will receive an email that allows
  /// them to revoke the email address change, in order to protect them
  /// from account hijacking.
  ///
  /// **Important**: This is a security sensitive operation that requires
  /// the user to have recently signed in.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the email address is malformed.
  ///   • `ERROR_EMAIL_ALREADY_IN_USE` - If the email is already in use by a different account.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_USER_NOT_FOUND` - If the user has been deleted (for example, in the Firebase console)
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Email & Password accounts are not enabled.
  ///
  Future<void> updateEmail(String email) async {
    assert(email != null);
    return await FirebaseAuth.channel.invokeMethod(
      'updateEmail',
      <String, String>{'email': email},
    );
  }

  /// Updates the password of the user.
  ///
  /// Anonymous users who update both their email and password will no
  /// longer be anonymous. They will be able to log in with these credentials.
  ///
  /// **Important**: This is a security sensitive operation that requires
  /// the user to have recently signed in.
  ///
  /// Errors:
  ///   • `ERROR_WEAK_PASSWORD` - If the password is not strong enough.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_USER_NOT_FOUND` - If the user has been deleted (for example, in the Firebase console)
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Email & Password accounts are not enabled.
  ///
  Future<void> updatePassword(String password) async {
    assert(password != null);
    return await FirebaseAuth.channel.invokeMethod(
      'updatePassword',
      <String, String>{'password': password},
    );
  }

  /// Updates the user profile information.
  ///
  /// Errors:
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_USER_NOT_FOUND` - If the user has been deleted (for example, in the Firebase console)
  ///
  Future<void> updateProfile(UserUpdateInfo userUpdateInfo) async {
    assert(userUpdateInfo != null);
    return await FirebaseAuth.channel.invokeMethod(
      'updateProfile',
      userUpdateInfo._updateData,
    );
  }

  /// Detaches Email & Password from this user.
  ///
  /// This detaches the Email & Password from the current user. This will
  /// prevent the user from signing in to this account with those credentials.
  ///
  /// **Important**: This is a security sensitive operation that requires
  /// the user to have recently signed in.
  ///
  /// Errors:
  ///   • `ERROR_NO_SUCH_PROVIDER` - If the user does not have an Email & Password linked to their account.
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///
  Future<void> unlinkEmailAndPassword() async {
    return await FirebaseAuth.channel.invokeMethod(
      'unlinkCredential',
      const <String, String>{'provider': 'password'},
    );
  }

  /// Detaches Google from this user.
  ///
  /// This detaches the Google Account from the current user. This will
  /// prevent the user from signing in to this account with those credentials.
  ///
  /// **Important**: This is a security sensitive operation that requires
  /// the user to have recently signed in.
  ///
  /// Errors:
  ///   • `ERROR_NO_SUCH_PROVIDER` - If the user does not have a Google Account linked to their account.
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///
  Future<void> unlinkGoogleCredential() async {
    return await FirebaseAuth.channel.invokeMethod(
      'unlinkCredential',
      const <String, String>{'provider': 'google.com'},
    );
  }

  /// Detaches Facebook from this user.
  ///
  /// This detaches the Facebook Account from the current user. This will
  /// prevent the user from signing in to this account with those credentials.
  ///
  /// **Important**: This is a security sensitive operation that requires
  /// the user to have recently signed in.
  ///
  /// Errors:
  ///   • `ERROR_NO_SUCH_PROVIDER` - If the user does not have a Facebook Account linked to their account.
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///
  Future<void> unlinkFacebookCredential() async {
    return await FirebaseAuth.channel.invokeMethod(
      'unlinkCredential',
      const <String, String>{'provider': 'facebook.com'},
    );
  }

  /// Detaches Twitter from this user.
  ///
  /// This detaches the Twitter Account from the current user. This will
  /// prevent the user from signing in to this account with those credentials.
  ///
  /// **Important**: This is a security sensitive operation that requires
  /// the user to have recently signed in.
  ///
  /// Errors:
  ///   • `ERROR_NO_SUCH_PROVIDER` - If the user does not have a Twitter Account linked to their account.
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///
  Future<void> unlinkTwitterCredential() async {
    return await FirebaseAuth.channel.invokeMethod(
      'unlinkCredential',
      const <String, String>{'provider': 'twitter.com'},
    );
  }

  @override
  String toString() {
    return '$runtimeType($_data)';
  }
}

class AuthException implements Exception {
  final String code;
  final String message;
  const AuthException(this.code, this.message);
}

typedef void PhoneVerificationCompleted(FirebaseUser firebaseUser);
typedef void PhoneVerificationFailed(AuthException error);
typedef void PhoneCodeSent(String verificationId, [int forceResendingToken]);
typedef void PhoneCodeAutoRetrievalTimeout(String verificationId);

class FirebaseAuth {
  @visibleForTesting
  static const MethodChannel channel = MethodChannel(
    'plugins.flutter.io/firebase_auth',
  );

  final Map<int, StreamController<FirebaseUser>> _authStateChangedControllers =
      <int, StreamController<FirebaseUser>>{};

  static int nextHandle = 0;
  final Map<int, Map<String, dynamic>> _phoneAuthCallbacks =
      <int, Map<String, dynamic>>{};

  /// Provides an instance of this class corresponding to the default app.
  ///
  /// TODO(jackson): Support for non-default apps.
  static FirebaseAuth instance = new FirebaseAuth._();

  FirebaseAuth._() {
    channel.setMethodCallHandler(_callHandler);
  }

  /// Receive [FirebaseUser] each time the user signIn or signOut or has changed.
  Stream<FirebaseUser> get onAuthStateChanged {
    Future<int> _handle;

    StreamController<FirebaseUser> controller;
    controller = new StreamController<FirebaseUser>.broadcast(onListen: () {
      _handle = channel
          .invokeMethod('startListeningAuthState')
          .then<int>((dynamic v) => v);
      _handle.then((int handle) {
        _authStateChangedControllers[handle] = controller;
      });
    }, onCancel: () {
      _handle.then((int handle) async {
        await channel.invokeMethod(
            "stopListeningAuthState", <String, int>{"id": handle});
        _authStateChangedControllers.remove(handle);
      });
    });

    return controller.stream;
  }

  /// Asynchronously creates and becomes an anonymous user.
  ///
  /// If there is already an anonymous user signed in, that user will be
  /// returned instead. If there is any other existing user signed in, that
  /// user will be signed out.
  ///
  /// **Important**: You must enable Anonymous accounts in the Auth section
  /// of the Firebase console before being able to use them.
  ///
  /// Errors:
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Anonymous accounts are not enabled.
  ///
  Future<FirebaseUser> signInAnonymously() async {
    final Map<dynamic, dynamic> data =
        await channel.invokeMethod('signInAnonymously');
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Tries to create a new user account with the given email address and password.
  ///
  /// If successful, it also signs the user in into the app and updates
  /// the [onAuthStateChanged] stream.
  ///
  /// Errors:
  ///   • `ERROR_WEAK_PASSWORD` - If the password is not strong enough.
  ///   • `ERROR_INVALID_CREDENTIAL` - If the email address is malformed.
  ///   • `ERROR_EMAIL_ALREADY_IN_USE` - If the email is already in use by a different account.
  ///
  Future<FirebaseUser> createUserWithEmailAndPassword({
    @required String email,
    @required String password,
  }) async {
    assert(email != null);
    assert(password != null);
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'createUserWithEmailAndPassword',
      <String, String>{
        'email': email,
        'password': password,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  @Deprecated("Please use fetchSignInMethodsForEmail() instead.")
  Future<List<String>> fetchProvidersForEmail({
    @required String email,
  }) =>
      fetchSignInMethodsForEmail(email: email);

  /// Returns a list of sign-in methods that can be used to sign in a given
  /// user (identified by its main email address).
  ///
  /// This method is useful when you support multiple authentication mechanisms
  /// if you want to implement an email-first authentication flow.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the [email] address is malformed.
  ///   • `ERROR_USER_NOT_FOUND` - If there is no user corresponding to the given [email] address.
  ///
  Future<List<String>> fetchSignInMethodsForEmail({
    @required String email,
  }) async {
    assert(email != null);
    final List<dynamic> providers = await channel.invokeMethod(
      'fetchSignInMethodsForEmail',
      <String, String>{
        'email': email,
      },
    );
    return providers?.cast<String>();
  }

  /// Triggers the Firebase Authentication backend to send a password-reset
  /// email to the given email address, which must correspond to an existing
  /// user of your app.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_EMAIL` - If the [email] address is malformed.
  ///   • `ERROR_USER_NOT_FOUND` - If there is no user corresponding to the given [email] address.
  ///
  Future<void> sendPasswordResetEmail({
    @required String email,
  }) async {
    assert(email != null);
    return await channel.invokeMethod(
      'sendPasswordResetEmail',
      <String, String>{
        'email': email,
      },
    );
  }

  /// Tries to sign in a user with the given email address and password.
  ///
  /// If successful, it also signs the user in into the app and updates
  /// the [onAuthStateChanged] stream.
  ///
  /// **Important**: You must enable Email & Password accounts in the Auth
  /// section of the Firebase console before being able to use them.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_EMAIL` - If the [email] address is malformed.
  ///   • `ERROR_WRONG_PASSWORD` - If the [password] is wrong.
  ///   • `ERROR_USER_NOT_FOUND` - If there is no user corresponding to the given [email] address, or if the user has been deleted.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_TOO_MANY_REQUESTS` - If there was too many attempts to sign in as this user.
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Email & Password accounts are not enabled.
  ///
  Future<FirebaseUser> signInWithEmailAndPassword({
    @required String email,
    @required String password,
  }) async {
    assert(email != null);
    assert(password != null);
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'signInWithEmailAndPassword',
      <String, String>{
        'email': email,
        'password': password,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Tries to sign in a user with the given Google [idToken] and [accessToken].
  ///
  /// If successful, it also signs the user in into the app and updates
  /// the [onAuthStateChanged] stream.
  ///
  /// If the user doesn't have an account already, one will be created automatically.
  ///
  /// **Important**: You must enable Google accounts in the Auth section
  /// of the Firebase console before being able to use them.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the [authToken] or [authTokenSecret] is malformed or has expired.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL` - If there already exists an account with the email address asserted by Google.
  ///       Resolve this case by calling [fetchSignInMethodsForEmail] and then asking the user to sign in using one of them.
  ///       This error will only be thrown if the "One account per email address" setting is enabled in the Firebase console (recommended).
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Google accounts are not enabled.
  ///
  Future<FirebaseUser> signInWithGoogle({
    @required String idToken,
    @required String accessToken,
  }) async {
    assert(idToken != null);
    assert(accessToken != null);
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'signInWithGoogle',
      <String, String>{
        'idToken': idToken,
        'accessToken': accessToken,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Tries to sign in a user with the given Facebook [accessToken].
  ///
  /// If successful, it also signs the user in into the app and updates
  /// the [onAuthStateChanged] stream.
  ///
  /// If the user doesn't have an account already, one will be created automatically.
  ///
  /// **Important**: You must enable Facebook accounts in the Auth section
  /// of the Firebase console before being able to use them.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the [accessToken] is malformed or has expired.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL` - If there already exists an account with the email address asserted by Facebook.
  ///       Resolve this case by calling [fetchSignInMethodsForEmail] and then asking the user to sign in using one of them.
  ///       This error will only be thrown if the "One account per email address" setting is enabled in the Firebase console (recommended).
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Facebook accounts are not enabled.
  ///
  Future<FirebaseUser> signInWithFacebook(
      {@required String accessToken}) async {
    assert(accessToken != null);
    final Map<dynamic, dynamic> data =
        await channel.invokeMethod('signInWithFacebook', <String, String>{
      'accessToken': accessToken,
    });
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Tries to sign in a user with the given Twitter [authToken] and [authTokenSecret].
  ///
  /// If successful, it also signs the user in into the app and updates
  /// the [onAuthStateChanged] stream.
  ///
  /// If the user doesn't have an account already, one will be created automatically.
  ///
  /// **Important**: You must enable Twitter accounts in the Auth section
  /// of the Firebase console before being able to use them.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the [authToken] or [authTokenSecret] is malformed or has expired.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_ACCOUNT_EXISTS_WITH_DIFFERENT_CREDENTIAL` - If there already exists an account with the email address asserted by Twitter.
  ///       Resolve this case by calling [fetchSignInMethodsForEmail] and then asking the user to sign in using one of them.
  ///       This error will only be thrown if the "One account per email address" setting is enabled in the Firebase console (recommended).
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Twitter accounts are not enabled.
  ///
  Future<FirebaseUser> signInWithTwitter({
    @required String authToken,
    @required String authTokenSecret,
  }) async {
    assert(authToken != null);
    assert(authTokenSecret != null);
    final Map<dynamic, dynamic> data =
        await channel.invokeMethod('signInWithTwitter', <String, String>{
      'authToken': authToken,
      'authTokenSecret': authTokenSecret,
    });
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Tries to sign in a user with the given Phone [verificationId] and [smsCode].
  ///
  /// If successful, it also signs the user in into the app and updates
  /// the [onAuthStateChanged] stream.
  ///
  /// If the user doesn't have an account already, one will be created automatically.
  ///
  /// **Important**: You must enable Phone accounts in the Auth section
  /// of the Firebase console before being able to use them.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the [verificationId] or [smsCode] is malformed or has expired.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Phone accounts are not enabled.
  ///
  Future<FirebaseUser> signInWithPhoneNumber({
    @required String verificationId,
    @required String smsCode,
  }) async {
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'signInWithPhoneNumber',
      <String, String>{
        'verificationId': verificationId,
        'smsCode': smsCode,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Starts the phone number verification process for the given phone number.
  ///
  /// Either sends an SMS with a 6 digit code to the phone number specified,
  /// or sign's the user in and [verificationCompleted] is called.
  ///
  /// No duplicated SMS will be sent out upon re-entry (before timeout).
  ///
  /// Make sure to test all scenarios below:
  ///   • You directly get logged in if Google Play Services verified the phone
  ///     number instantly or helped you auto-retrieve the verification code.
  ///   • Auto-retrieve verification code timed out.
  ///   • Error cases when you receive [verificationFailed] callback.
  ///
  /// [phoneNumber] The phone number for the account the user is signing up
  ///   for or signing into. Make sure to pass in a phone number with country
  ///   code prefixed with plus sign ('+').
  ///
  /// [timeout] The maximum amount of time you are willing to wait for SMS
  ///   auto-retrieval to be completed by the library. Maximum allowed value
  ///   is 2 minutes. Use 0 to disable SMS-auto-retrieval. Setting this to 0
  ///   will also cause [codeAutoRetrievalTimeout] to be called immediately.
  ///   If you specified a positive value less than 30 seconds, library will
  ///   default to 30 seconds.
  ///
  /// [forceResendingToken] The [forceResendingToken] obtained from [codeSent]
  ///   callback to force re-sending another verification SMS before the
  ///   auto-retrieval timeout.
  ///
  /// [verificationCompleted] This callback must be implemented.
  ///   It will trigger when an SMS is auto-retrieved or the phone number has
  ///   been instantly verified. The callback will provide a [FirebaseUser].
  ///
  /// [verificationFailed] This callback must be implemented.
  ///   Triggered when an error occurred during phone number verification.
  ///
  /// [codeSent] Optional callback.
  ///   It will trigger when an SMS has been sent to the users phone,
  ///   and will include a [verificationId] and [forceResendingToken].
  ///
  /// [codeAutoRetrievalTimeout] Optional callback.
  ///   It will trigger when SMS auto-retrieval times out and provide a
  ///   [verificationId].
  ///
  Future<void> verifyPhoneNumber({
    @required String phoneNumber,
    @required Duration timeout,
    int forceResendingToken,
    @required PhoneVerificationCompleted verificationCompleted,
    @required PhoneVerificationFailed verificationFailed,
    @required PhoneCodeSent codeSent,
    @required PhoneCodeAutoRetrievalTimeout codeAutoRetrievalTimeout,
  }) async {
    final Map<String, dynamic> callbacks = <String, dynamic>{
      'PhoneVerificationCompleted': verificationCompleted,
      'PhoneVerificationFailed': verificationFailed,
      'PhoneCodeSent': codeSent,
      'PhoneCodeAuthRetrievalTimeout': codeAutoRetrievalTimeout,
    };
    nextHandle += 1;
    _phoneAuthCallbacks[nextHandle] = callbacks;

    final Map<String, dynamic> params = <String, dynamic>{
      'handle': nextHandle,
      'phoneNumber': phoneNumber,
      'timeout': timeout.inMilliseconds,
      'forceResendingToken': forceResendingToken,
    };

    await channel.invokeMethod('verifyPhoneNumber', params);
  }

  /// Tries to sign in a user with a given Custom Token [token].
  ///
  /// If successful, it also signs the user in into the app and updates
  /// the [onAuthStateChanged] stream.
  ///
  /// Use this method after you retrieve a Firebase Auth Custom Token from your server.
  ///
  /// If the user identified by the [uid] specified in the token doesn't
  /// have an account already, one will be created automatically.
  ///
  /// Read how to use Custom Token authentication and the cases where it is
  /// useful in [the guides](https://firebase.google.com/docs/auth/android/custom-auth).
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CUSTOM_TOKEN` - The custom token format is incorrect.
  ///     Please check the documentation.
  ///   • `ERROR_CUSTOM_TOKEN_MISMATCH` - Invalid configuration.
  ///     Ensure your app's SHA1 is correct in the Firebase console.
  ///
  Future<FirebaseUser> signInWithCustomToken({@required String token}) async {
    assert(token != null);
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'signInWithCustomToken',
      <String, String>{
        'token': token,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Signs out the current user and clears it from the disk cache.
  ///
  /// If successful, it signs the user out of the app and updates
  /// the [onAuthStateChanged] stream.
  ///
  Future<void> signOut() async {
    return await channel.invokeMethod("signOut");
  }

  /// Returns the currently signed-in [FirebaseUser] or [null] if there is none.
  Future<FirebaseUser> currentUser() async {
    final Map<dynamic, dynamic> data =
        await channel.invokeMethod("currentUser");
    final FirebaseUser currentUser =
        data == null ? null : new FirebaseUser._(data);
    return currentUser;
  }

  /// Links the given [email] and [password] to the current user.
  ///
  /// This allows the user to sign in to this account in the future with
  /// the given [email] and [password].
  ///
  /// Errors:
  ///   • `ERROR_WEAK_PASSWORD` - If the password is not strong enough.
  ///   • `ERROR_INVALID_CREDENTIAL` - If the email address is malformed.
  ///   • `ERROR_CREDENTIAL_ALREADY_IN_USE` - If the email is already in use by a different account.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///   • `ERROR_PROVIDER_ALREADY_LINKED` - If the current user already has an Email & Password linked.
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Email & Password accounts are not enabled.
  ///
  Future<FirebaseUser> linkWithEmailAndPassword({
    @required String email,
    @required String password,
  }) async {
    assert(email != null);
    assert(password != null);
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'linkWithEmailAndPassword',
      <String, String>{
        'email': email,
        'password': password,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Links the Google Account to the current user using [idToken] and [accessToken].
  ///
  /// This allows the user to sign in to this account in the future with
  /// the given Google Account.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the [authToken] or [authTokenSecret] is malformed or has expired.
  ///   • `ERROR_CREDENTIAL_ALREADY_IN_USE` - If the Google account is already in use by a different account.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///   • `ERROR_PROVIDER_ALREADY_LINKED` - If the current user already has a Google account linked.
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Google accounts are not enabled.
  ///
  Future<FirebaseUser> linkWithGoogleCredential({
    @required String idToken,
    @required String accessToken,
  }) async {
    assert(idToken != null);
    assert(accessToken != null);
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'linkWithGoogleCredential',
      <String, String>{
        'idToken': idToken,
        'accessToken': accessToken,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Links the Facebook Account to the current user using [accessToken].
  ///
  /// This allows the user to sign in to this account in the future with
  /// the given Facebook Account.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the [accessToken] is malformed or has expired.
  ///   • `ERROR_CREDENTIAL_ALREADY_IN_USE` - If the Facebook account is already in use by a different account.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///   • `ERROR_PROVIDER_ALREADY_LINKED` - If the current user already has a Facebook account linked.
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Facebook accounts are not enabled.
  ///
  Future<FirebaseUser> linkWithFacebookCredential({
    @required String accessToken,
  }) async {
    assert(accessToken != null);
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'linkWithFacebookCredential',
      <String, String>{
        'accessToken': accessToken,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Links the Twitter Account to the current user using [authToken] and [authTokenSecret].
  ///
  /// This allows the user to sign in to this account in the future with
  /// the given Twitter Account.
  ///
  /// Errors:
  ///   • `ERROR_INVALID_CREDENTIAL` - If the [authToken] or [authTokenSecret] is malformed or has expired.
  ///   • `ERROR_CREDENTIAL_ALREADY_IN_USE` - If the Twitter account is already in use by a different account.
  ///   • `ERROR_USER_DISABLED` - If the user has been disabled (for example, in the Firebase console)
  ///   • `ERROR_REQUIRES_RECENT_LOGIN` - If the user's last sign-in time does not meet the security threshold.
  ///   • `ERROR_PROVIDER_ALREADY_LINKED` - If the current user already has a Twitter account linked.
  ///   • `ERROR_OPERATION_NOT_ALLOWED` - Indicates that Twitter accounts are not enabled.
  ///
  Future<FirebaseUser> linkWithTwitterCredential({
    @required String authToken,
    @required String authTokenSecret,
  }) async {
    assert(authToken != null);
    assert(authTokenSecret != null);
    final Map<dynamic, dynamic> data = await channel.invokeMethod(
      'linkWithTwitterCredential',
      <String, String>{
        'authToken': authToken,
        'authTokenSecret': authTokenSecret,
      },
    );
    final FirebaseUser currentUser = new FirebaseUser._(data);
    return currentUser;
  }

  /// Sets the user-facing language code for auth operations that can be
  /// internationalized, such as [sendEmailVerification]. This language
  /// code should follow the conventions defined by the IETF in BCP47.
  Future<void> setLanguageCode(String language) async {
    assert(language != null);
    await FirebaseAuth.channel.invokeMethod('setLanguageCode', <String, String>{
      'language': language,
    });
  }

  Future<Null> _callHandler(MethodCall call) async {
    switch (call.method) {
      case 'onAuthStateChanged':
        _onAuthStageChangedHandler(call);
        break;
      case 'phoneVerificationCompleted':
        final int handle = call.arguments['handle'];
        final PhoneVerificationCompleted verificationCompleted =
            _phoneAuthCallbacks[handle]['PhoneVerificationCompleted'];
        verificationCompleted(await currentUser());
        break;
      case 'phoneVerificationFailed':
        final int handle = call.arguments['handle'];
        final PhoneVerificationFailed verificationFailed =
            _phoneAuthCallbacks[handle]['PhoneVerificationFailed'];
        final Map<dynamic, dynamic> exception = call.arguments['exception'];
        verificationFailed(
            new AuthException(exception['code'], exception['message']));
        break;
      case 'phoneCodeSent':
        final int handle = call.arguments['handle'];
        final String verificationId = call.arguments['verificationId'];
        final int forceResendingToken = call.arguments['forceResendingToken'];

        final PhoneCodeSent codeSent =
            _phoneAuthCallbacks[handle]['PhoneCodeSent'];
        if (forceResendingToken == null) {
          codeSent(verificationId);
        } else {
          codeSent(verificationId, forceResendingToken);
        }
        break;
      case 'phoneCodeAutoRetrievalTimeout':
        final int handle = call.arguments['handle'];
        final PhoneCodeAutoRetrievalTimeout codeAutoRetrievalTimeout =
            _phoneAuthCallbacks[handle]['PhoneCodeAutoRetrievealTimeout'];
        final String verificationId = call.arguments['verificationId'];
        codeAutoRetrievalTimeout(verificationId);
        break;
    }
    return null;
  }

  void _onAuthStageChangedHandler(MethodCall call) {
    final Map<dynamic, dynamic> data = call.arguments["user"];
    final int id = call.arguments["id"];

    final FirebaseUser currentUser =
        data != null ? new FirebaseUser._(data) : null;
    _authStateChangedControllers[id].add(currentUser);
  }
}
