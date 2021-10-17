/// Utilities for processing binary formats of SSH keys.
///
/// This library is for internal use by the `ssh_key` library.
/// Normal programs do not need to directly access the classes in this library.
///
/// In general, a SSH key file format contains the text encoding of a binary
/// format. That binary format is a generic data structure that is used to
/// store different data, depending on the public-key algorithm.
/// This library implements code to process the binary formats.

library ssh_key_bin;

//----------------------------------------------------------------

import 'dart:convert';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';

import 'package:ssh_key/ssh_key_txt.dart';
import 'package:ssh_key/ssh_key.dart' show KeyUnsupported, KeyBad;

//----------------------------------------------------------------

part 'src/binary_formats/asn1_util.dart';
part 'src/binary_formats/binary_format.dart';
part 'src/binary_formats/binary_length_value.dart';
part 'src/binary_formats/binary_range.dart';
part 'src/binary_formats/hexdump.dart';
part 'src/binary_formats/openssh_private_key.dart';
part 'src/binary_formats/pkcs1_public_key.dart';
part 'src/binary_formats/pkcs1_private_key.dart';
part 'src/binary_formats/subject_public_key_info.dart';
