#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
from pathlib import Path
import argparse
import struct

ENCODING = 'shift_jis'
DT_EXTENSION = '._dt'
JSON_EXTENSION = '.json'

def read_file_header(file_data):
    """Read and validate file header"""
    if len(file_data) < 4:
        raise ValueError("File too small")

    header_size = struct.unpack('<H', file_data[0:2])[0]
    if header_size < 2 or header_size >= len(file_data):
        raise ValueError(f"Invalid header size: {header_size}")

    return header_size

def read_offsets_from_block(data_block, start_pos=0):
    """Read all offsets from data block"""
    offsets = []
    for i in range(start_pos, len(data_block) - 1, 2):
        offset = struct.unpack('<H', data_block[i:i+2])[0]
        offsets.append(offset)
    return offsets

def extract_string_at_offset(file_data, offset):
    """Extract null-terminated string at given offset (including empty strings)"""
    if offset >= len(file_data):
        return ""

    null_pos = file_data.find(b'\x00', offset)
    if null_pos == -1:
        null_pos = len(file_data)

    try:
        return file_data[offset:null_pos].decode(ENCODING, errors='replace')
    except:
        return file_data[offset:null_pos].decode('utf-8', errors='replace')

def decompile_dt(dt_path, json_path, test_compilation=False):
    """Decompile DT file - unified approach"""
    print(f"=== DECOMPILING {dt_path} ===")

    with open(dt_path, 'rb') as f:
        original_data = f.read()

    print(f"File size: {len(original_data)} bytes")

    # Read structure
    header_size = read_file_header(original_data)

    # Read offsets from header
    header_offsets = read_offsets_from_block(original_data, 2)  # skip first 2 bytes (size)
    header_offsets = header_offsets[:(header_size - 2) // 2]  # only needed amount

    first_offset = header_offsets[0]
    metadata_block = original_data[header_size:first_offset]

    # Read offsets from metadata block
    metadata_offsets = read_offsets_from_block(metadata_block)

    print(f"Header: {header_size} bytes, Metadata: {len(metadata_block)} bytes")
    print(f"Header offsets: {len(header_offsets)}, Metadata offsets: {len(metadata_offsets)}")

    # Combine ALL offsets and sort them
    all_offsets = header_offsets + metadata_offsets
    all_offsets = sorted(set(all_offsets))  # remove duplicates and sort

    print(f"Total unique offsets: {len(all_offsets)}")

    # Extract ALL strings from all offsets (including empty ones)
    all_strings = []
    for offset in all_offsets:
        text = extract_string_at_offset(original_data, offset)
        all_strings.append(text)

    # Count statistics
    non_empty = [s for s in all_strings if s.strip()]
    empty_count = len(all_strings) - len(non_empty)

    print(f"Extracted {len(all_strings)} strings total ({len(non_empty)} non-empty, {empty_count} empty)")

    # Create simple JSON structure
    result = {
        "file_info": {
            "original_size": len(original_data),
            "encoding": ENCODING
        },
        "structure": {
            "header_size": header_size,
            "header_offset_count": len(header_offsets),
            "metadata_offset_count": len(metadata_offsets),
            "metadata_hex": metadata_block.hex()
        },
        "strings": all_strings
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\n✓ Decompiled to {json_path}")
    print(f"📝 Edit 'strings' array for translation")
    print(f"ℹ️  All strings are editable (including empty ones)")

    if test_compilation:
        test_compilation_process(dt_path, json_path, original_data)

def compile_dt(json_path, dt_path):
    """Compile JSON back to DT file"""
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print(f"Original size: {data['file_info']['original_size']} bytes")
    print(f"Strings to compile: {len(data['strings'])}")

    # Start building file
    result_data = bytearray()

    # Reserve space for header
    header_size = data['structure']['header_size']
    result_data.extend(b'\x00' * header_size)

    # Reserve space for metadata block
    metadata_size = len(bytes.fromhex(data['structure']['metadata_hex']))
    result_data.extend(b'\x00' * metadata_size)

    # Write ALL strings sequentially and collect new offsets
    new_offsets = []

    for i, text in enumerate(data['strings']):
        current_offset = len(result_data)
        new_offsets.append(current_offset)

        # Encode string + null terminator + padding null
        encoded_text = text.encode(data['file_info']['encoding']) + b'\x00\x00'

        result_data.extend(encoded_text)

    print(f"Built {len(new_offsets)} strings, total size: {len(result_data)} bytes")

    # Split offsets back into header and metadata blocks
    header_offset_count = data['structure']['header_offset_count']
    metadata_offset_count = data['structure']['metadata_offset_count']

    header_offsets = new_offsets[:header_offset_count]
    metadata_offsets = new_offsets[header_offset_count:header_offset_count + metadata_offset_count]

    # Pad if needed
    while len(header_offsets) < header_offset_count:
        header_offsets.append(len(result_data))
    while len(metadata_offsets) < metadata_offset_count:
        metadata_offsets.append(len(result_data))

    print(f"Header offsets: {len(header_offsets)}, Metadata offsets: {len(metadata_offsets)}")

    # Build header
    header = bytearray()
    header.extend(struct.pack('<H', header_size))

    for offset in header_offsets:
        if offset > 0xFFFF:
            print(f"WARNING: Header offset {offset} too large for 2-byte field!")
            offset = 0xFFFF
        header.extend(struct.pack('<H', offset))

    # Pad header with zeros
    while len(header) < header_size:
        header.append(0)

    # Build metadata block
    metadata = bytearray()
    for offset in metadata_offsets:
        if offset > 0xFFFF:
            print(f"WARNING: Metadata offset {offset} too large for 2-byte field!")
            offset = 0xFFFF
        metadata.extend(struct.pack('<H', offset))

    # Pad metadata with zeros
    while len(metadata) < metadata_size:
        metadata.append(0)

    # Write header and metadata
    result_data[:header_size] = header
    result_data[header_size:header_size + metadata_size] = metadata

    # Save file
    with open(dt_path, 'wb') as f:
        f.write(result_data)

    print(f"\n✓ Compiled to {dt_path}")
    print(f"New size: {len(result_data)} bytes")
    print(f"Size difference: {len(result_data) - data['file_info']['original_size']:+d} bytes")

def test_compilation_process(dt_path, json_path, original_data):
    """Test compilation process"""
    print("\n=== COMPILATION TEST ===")
    test_dt_path = dt_path.parent / f"{dt_path.stem}_test{dt_path.suffix}"

    try:
        compile_dt(json_path, test_dt_path)

        with open(test_dt_path, 'rb') as f:
            compiled_data = f.read()

        if compiled_data == original_data:
            print("✅ TEST PASSED: Files are identical!")
            test_dt_path.unlink()
        else:
            print(f"❌ TEST FAILED:")
            print(f"  Original: {len(original_data)} bytes")
            print(f"  Compiled: {len(compiled_data)} bytes")
            print(f"  Difference: {len(compiled_data) - len(original_data):+d} bytes")

            # Find first difference
            min_len = min(len(original_data), len(compiled_data))
            for i in range(min_len):
                if original_data[i] != compiled_data[i]:
                    print(f"  First difference at position {i}: {original_data[i]:02x} → {compiled_data[i]:02x}")
                    break

            print(f"  Test file saved: {test_dt_path}")

    except Exception as e:
        print(f"❌ Error during testing: {e}")
        import traceback
        traceback.print_exc()

def determine_file_type(input_path):
    """Determine if input file is DT or JSON"""
    if input_path.suffix.lower() == JSON_EXTENSION:
        return 'json'
    elif input_path.name.endswith(DT_EXTENSION):
        return 'dt'
    else:
        return 'unknown'

def main():
    parser = argparse.ArgumentParser(description="Unified _DT file decompiler/compiler")
    parser.add_argument("input_file", help="Input file (._dt or .json)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--test", action="store_true", help="Test compilation after decompilation")

    args = parser.parse_args()
    input_path = Path(args.input_file)

    if not input_path.exists():
        print(f"File not found: {input_path}")
        sys.exit(1)

    file_type = determine_file_type(input_path)

    if file_type == 'json':
        output_path = Path(args.output) if args.output else input_path.with_suffix(DT_EXTENSION)
        compile_dt(input_path, output_path)
    elif file_type == 'dt':
        output_path = Path(args.output) if args.output else input_path.with_suffix(JSON_EXTENSION)
        decompile_dt(input_path, output_path, test_compilation=args.test)
    else:
        print(f"Unsupported file: {input_path}")
        print(f"Supported: {JSON_EXTENSION} (for compilation) and {DT_EXTENSION} (for decompilation)")
        sys.exit(1)

if __name__ == "__main__":
    main()