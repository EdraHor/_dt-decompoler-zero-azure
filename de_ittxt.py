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

def read_offsets(file_data, header_size):
    """Read all offsets from file header"""
    offset_count = (header_size - 2) // 2
    offsets = []

    for i in range(offset_count):
        pos = 2 + i * 2
        if pos + 2 > header_size:
            break
        offset = struct.unpack('<H', file_data[pos:pos+2])[0]
        offsets.append(offset)

    return offsets

def extract_string_at_offset(file_data, offset):
    """Extract null-terminated string at given offset"""
    if offset >= len(file_data):
        return ""

    null_pos = file_data.find(b'\x00', offset)
    if null_pos == -1:
        null_pos = len(file_data)

    try:
        return file_data[offset:null_pos].decode(ENCODING, errors='replace')
    except:
        return file_data[offset:null_pos].decode('utf-8', errors='replace')

def extract_additional_data_block(file_data, start_offset):
    """Extract all remaining data after last main string as single block"""
    if start_offset >= len(file_data):
        return [], b""

    # Весь блок данных после последней основной строки
    remaining_block = file_data[start_offset:]

    # Для удобства переводчика - показать какие строки в этом блоке
    preview_strings = []
    current_pos = 0

    while current_pos < len(remaining_block):
        # Пропускаем null байты
        while current_pos < len(remaining_block) and remaining_block[current_pos] == 0:
            current_pos += 1

        if current_pos >= len(remaining_block):
            break

        # Найти конец строки
        string_end = current_pos
        while string_end < len(remaining_block) and remaining_block[string_end] != 0:
            string_end += 1

        if string_end > current_pos:
            try:
                text = remaining_block[current_pos:string_end].decode(ENCODING, errors='replace')
                if text.strip():  # Игнорируем пустые строки
                    preview_strings.append(text)
            except:
                pass

        current_pos = string_end + 1

    return preview_strings, remaining_block

def decompile_dt(dt_path, json_path, test_compilation=False):
    """Decompile DT file to simple JSON structure"""
    print(f"=== DECOMPILING {dt_path} ===")

    with open(dt_path, 'rb') as f:
        original_data = f.read()

    print(f"File size: {len(original_data)} bytes")

    # Читаем структуру
    header_size = read_file_header(original_data)
    offsets = read_offsets(original_data, header_size)
    first_offset = offsets[0]
    metadata_block = original_data[header_size:first_offset]

    print(f"Header: {header_size} bytes, Metadata: {len(metadata_block)} bytes, Offsets: {len(offsets)}")

    # Извлекаем основные строки (все кроме последней)
    main_strings = []
    for offset in offsets[:-1]:
        text = extract_string_at_offset(original_data, offset)
        main_strings.append(text)

    # Извлекаем последнюю строку
    last_offset = offsets[-1]
    last_string = extract_string_at_offset(original_data, last_offset)
    main_strings.append(last_string)

    # Ищем дополнительные данные после последней основной строки
    last_string_end = last_offset + len(last_string.encode(ENCODING)) + 1
    additional_preview, additional_data_block = extract_additional_data_block(original_data, last_string_end)

    print(f"Extracted {len(main_strings)} main strings")
    if additional_preview:
        print(f"Additional data contains {len(additional_preview)} strings: {', '.join(additional_preview[:3])}{'...' if len(additional_preview) > 3 else ''}")
    print(f"Preserved {len(additional_data_block)} bytes of additional data")

    # Создаем простую JSON структуру
    result = {
        "file_info": {
            "original_size": len(original_data),
            "encoding": ENCODING
        },
        "structure": {
            "header_size": header_size,
            "metadata_hex": metadata_block.hex()
        },
        "main_strings": main_strings,
        "additional_data_hex": additional_data_block.hex(),
        "additional_preview": additional_preview  # Только для информации
    }

    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"\n✓ Decompiled to {json_path}")
    if len(additional_data_block) > 0:
        print(f"📝 Edit 'main_strings' for translation")
        print(f"ℹ️  Additional data preserved as single block ({len(additional_data_block)} bytes)")
        if additional_preview:
            print(f"ℹ️  Contains: {', '.join(additional_preview[:5])}{'...' if len(additional_preview) > 5 else ''}")
    else:
        print(f"📝 Edit 'main_strings' for translation")

    if test_compilation:
        test_compilation_process(dt_path, json_path, original_data)

def compile_dt(json_path, dt_path):
    """Compile JSON back to DT file"""
    print(f"=== COMPILING {json_path} ===")

    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    print(f"Original size: {data['file_info']['original_size']} bytes")
    print(f"Main strings: {len(data['main_strings'])}")

    # Проверяем наличие дополнительных данных
    additional_data_hex = data.get('additional_data_hex', '')
    additional_data = bytes.fromhex(additional_data_hex) if additional_data_hex else b''
    if additional_data:
        additional_preview = data.get('additional_preview', [])
        print(f"Additional data: {len(additional_data)} bytes ({len(additional_preview)} strings)")

    # Начинаем строить файл
    result_data = bytearray()

    # Резервируем место под заголовок
    header_size = data['structure']['header_size']
    result_data.extend(b'\x00' * header_size)

    # Добавляем блок метаданных
    metadata_block = bytes.fromhex(data['structure']['metadata_hex'])
    result_data.extend(metadata_block)

    # Записываем основные строки (все кроме последней) + padding
    new_offsets = []

    for i, text in enumerate(data['main_strings'][:-1]):
        current_offset = len(result_data)
        new_offsets.append(current_offset)

        # Кодируем строку + null terminator + padding (еще один null)
        encoded_text = text.encode(data['file_info']['encoding']) + b'\x00\x00'
        result_data.extend(encoded_text)

    # Последняя основная строка
    last_offset = len(result_data)
    new_offsets.append(last_offset)

    last_string = data['main_strings'][-1]
    last_encoded = last_string.encode(data['file_info']['encoding']) + b'\x00'
    result_data.extend(last_encoded)

    # Восстанавливаем дополнительные данные (весь блок целиком)
    additional_data_hex = data.get('additional_data_hex', '')
    if additional_data_hex:
        additional_data = bytes.fromhex(additional_data_hex)
        result_data.extend(additional_data)

    print(f"Built {len(new_offsets)} string blocks, total data: {len(result_data)} bytes")

    # Дополняем offset'ы до нужного количества
    original_offset_count = (header_size - 2) // 2
    while len(new_offsets) < original_offset_count:
        new_offsets.append(len(result_data))

    new_offsets = new_offsets[:original_offset_count]

    # Строим заголовок
    header = bytearray()
    header.extend(struct.pack('<H', header_size))

    for offset in new_offsets:
        if offset > 0xFFFF:
            print(f"WARNING: Offset {offset} too large for 2-byte field!")
            offset = 0xFFFF
        header.extend(struct.pack('<H', offset))

    while len(header) < header_size:
        header.append(0)

    # Записываем заголовок
    result_data[:header_size] = header

    # Сохраняем файл
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

            # Найти первое различие
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
    parser = argparse.ArgumentParser(description="Clean _DT file decompiler/compiler")
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