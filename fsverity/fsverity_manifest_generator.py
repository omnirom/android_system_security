#!/usr/bin/env python3
#
# Copyright 2022 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
`fsverity_manifest_generator` generates the a manifest file containing digests
of target files.
"""

import argparse
import os
import subprocess
import sys
from fsverity_digests_pb2 import FSVerityDigests

HASH_ALGORITHM = 'sha256'

def _digest(fsverity_path, input_file):
  cmd = [fsverity_path, 'digest', input_file]
  cmd.extend(['--compact'])
  cmd.extend(['--hash-alg', HASH_ALGORITHM])
  out = subprocess.check_output(cmd, text=True).strip()
  return bytes(bytearray.fromhex(out))

if __name__ == '__main__':
  p = argparse.ArgumentParser(fromfile_prefix_chars='@')
  p.add_argument(
      '--output',
      help='Path to the output manifest',
      required=True)
  p.add_argument(
      '--fsverity-path',
      help='path to the fsverity program',
      required=True)
  p.add_argument(
      '--base-dir',
      help='directory to use as a relative root for the inputs. Also see the documentation of '
      'inputs')
  p.add_argument(
      'inputs',
      nargs='*',
      help='input file for the build manifest. It can be in either of two forms: <file> or '
      '<file>,<path_on_device>. If the first form is used, --base-dir must be provided, and the '
      'path on device will be the filepath relative to the base dir')
  args = p.parse_args()

  links = {}
  digests = FSVerityDigests()
  for f in sorted(args.inputs):
    if args.base_dir:
      # f is a full path for now; make it relative so it starts with {mount_point}/
      rel = os.path.relpath(f, args.base_dir)
    else:
      parts = f.split(',')
      if len(parts) != 2 or not parts[0] or not parts[1]:
        sys.exit("Since --base-path wasn't provided, all inputs must be pairs separated by commas "
          "but this input wasn't: " + f)
      f, rel = parts

    # Some fsv_meta files are links to other ones. Don't read through the link, because the
    # layout of files in the build system may not match the layout of files on the device.
    # Instead, read its target and use it to copy the digest from the real file after all files
    # are processed.
    if os.path.islink(f):
      links[rel] = os.path.normpath(os.path.join(os.path.dirname(rel), os.readlink(f)))
    else:
      digest = digests.digests[rel]
      digest.digest = _digest(args.fsverity_path, f)
      digest.hash_alg = HASH_ALGORITHM

  for link_rel, real_rel in links.items():
    if real_rel not in digests.digests:
      sys.exit(f'There was a fsv_meta symlink to {real_rel}, but that file was not a fsv_meta file')
    link_digest = digests.digests[link_rel]
    real_digest = digests.digests[real_rel]
    link_digest.CopyFrom(real_digest)

  # Serialize with deterministic=True for reproducible builds and build caching.
  # The serialized contents will still change across different versions of protobuf.
  manifest = digests.SerializeToString(deterministic=True)

  with open(args.output, "wb") as f:
    f.write(manifest)
