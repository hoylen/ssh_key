/// Utilities for processing text encodings of SSH keys.
///
/// This library is for internal use by the `ssh_key` library.
/// Normal programs do not need to directly access the classes in this library.
///
/// In general, a SSH key file format contains the text encoding of a binary
/// format. That binary format is a generic data structure that is used to
/// store different data, depending on the public-key algorithm.
/// This library implements code to process the text encodings.

library ssh_key_txt;

import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pointy_castle;

import 'package:ssh_key/ssh_key_bin.dart';
import 'package:ssh_key/ssh_key.dart'
    show PubKeyEncoding, PvtKeyEncoding, KeyMissing, KeyBad, KeyUnsupported;

//----------------------------------------------------------------

part 'src/text_encodings/openssh_public_key.dart';
part 'src/text_encodings/putty_private_key.dart';
part 'src/text_encodings/ssh_public_key.dart';
part 'src/text_encodings/text_encoding.dart';
part 'src/text_encodings/textual_encoding.dart';
