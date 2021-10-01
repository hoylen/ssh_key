part of ssh_key;

//################################################################
/// Name-value pairs for public keys.
///
/// Collection of name-value pair properties. Names are case-insensitive.
/// There can be multiple values for a given name. The names are unordered in
/// the collection of properties. But if there are multiple properties with the
/// same name, their values are ordered.
///
/// Properties are used to store the headers in the SSH Public Key (FRC 4716)
/// format. Properties completely support all the capability of headers, even
/// though in practice they are commonly used for one comment and maybe one
/// subject header. Other formats only support one optional comment, or nothing
/// at all.
///
/// Since having a single comment is the most common use of properties,
/// the [comment] getter and setter are provided as a convenient way to
/// access the first comment property. Multiple comment properties are not
/// supported when using the _comment_ getter and setter (but multiple comment
/// properties should not be used, even though RFC 4716 does not explicitly
/// prohibit them).

class Properties {
  //================================================================
  // Constructor

  //================================================================
  // Constants

  /// Name for the comment property.

  static const String commentName = 'Comment';

  //================================================================
  // Members

  //----------------------------------------------------------------
  /// Properties associated with the public key.
  ///
  /// Keys are case-insensitive.
  ///
  /// Used to store comments (for the OpenSSH format) and headers (for the
  /// RFC 4716 format).

  final Map<String, List<String>> _data = LinkedHashMap<String, List<String>>(
      equals: (a, b) => a.toLowerCase() == b.toLowerCase(),
      hashCode: (key) => key.toLowerCase().hashCode);

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Names of all the properties.
  ///
  /// To process every property, do something like this:
  ///
  /// ```
  /// for (final name in properties.keys) {
  ///     for (final value in properties.values(name)) {
  ///       // process "name" and "value"
  ///     }
  /// ```

  Iterable<String> get keys => _data.keys;

  //----------------------------------------------------------------
  /// All the values of a given named property.
  ///
  /// Returns null if there are no properties with the given name.

  Iterable<String>? values(String name) => _data[name];

  //----------------------------------------------------------------
  /// Number of properties.
  ///
  /// Returns the number of properties. This can be larger then the number of
  /// [keys], since multiple properties with the same _name_ are possible.

  int get length {
    var n = 0;
    for (final values in _data.values) {
      n += values.length;
    }
    return n;
  }

  //----------------------------------------------------------------
  /// Add a property.
  ///
  /// Add a new property with the [name] and [value] is added. If there is
  /// already such a property with that name, another one is added after it
  /// (even if it has the same value).

  void add(String name, String value) {
    var values = _data[name];

    if (values == null) {
      values = <String>[];
      _data[name] = values; // create member
    }

    values.add(value);
  }

  //----------------------------------------------------------------
  /// Remove all properties with a given name.
  ///
  /// Returns the number of properties that were removed.

  int remove(String name) {
    final victim = _data.remove(name);
    return victim?.length ?? 0;
  }

  //----------------------------------------------------------------
  /// Remove all properties.
  ///
  /// After this the properties is empty.

  void clear() {
    _data.clear();
  }

  //----------------------------------------------------------------
  /// Retrieves the first comment.
  ///
  /// Returns the value of the first comment. In the unlikely situation where
  /// there are more than one comment, the rest are ignored.
  ///
  /// Returns null if there is no comment property.

  String? get comment {
    final values = _data[commentName];

    if (values != null) {
      return values.first; // has comment
    } else {
      return null; // no comment: deliberately return null
    }
  }

  //----------------------------------------------------------------
  /// Sets the properties to have a comment.
  ///
  /// Sets the comment property to the given [value]. All previous comment
  /// properties are removed, if there was any.
  ///
  /// If the value is null, no new comment property is added. So the properties
  /// will not have any comment properties.

  set comment(String? value) {
    if (value != null) {
      _data[commentName] = [value]; // set all to just the one value
    } else {
      _data.remove(commentName); // remove all
    }
  }
}
