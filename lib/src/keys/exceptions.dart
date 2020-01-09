part of ssh_key;

//################################################################
/// Base class for exceptions from this package.

abstract class KeyException implements Exception {
  /// Constructor
  KeyException(this.type, this.message);

  /// The type of key exception
  String type;

  /// The error message
  String message;
  @override
  String toString() => '$type: $message';
}

//################################################################
/// Indicates a key could not be found in the text.

class KeyMissing extends KeyException {
  /// Constructor for a missing key exception
  KeyMissing(String message) : super('Key missing', message);
}

//################################################################
/// Indicates a key was found, but has bad data.

class KeyBad extends KeyException {
  /// Constructor for a bad key exception
  KeyBad(String message) : super('Key bad', message);
}

//################################################################
/// Indicates a key was found, but it is not supported by this implementation.
///
/// Namely, it is not an RSA key.

class KeyUnsupported extends KeyException {
  /// Constructor for an unsupported key exception
  KeyUnsupported(String message) : super('Key unsupported', message);
}
