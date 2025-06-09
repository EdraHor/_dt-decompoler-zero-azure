# _dt File Tool

Decompiler/compiler for `._dt` files from **Trails from Zero** and **Trails to Azure** games.

## Features

- Decompile binary `._dt` files to human-readable JSON format
- Compile JSON back to `._dt` files
- Drag & drop support

## Usage

### Basic Usage
```bash
# Decompile DT file to JSON
python dt_tool.py file._dt

# Compile JSON back to DT file  
python dt_tool.py file.json

# Specify custom output filename
python dt_tool.py file._dt -o my_output.json
```

### Advanced Usage
```bash
# Test compilation after decompilation (verify integrity)
python dt_tool.py file._dt --test
```

### Drag & Drop
You can also drag and drop `._dt` files directly onto the script for quick decompilation.

## JSON Format

The tool converts binary data into a readable JSON structure with:
- **Header information**: file size, encoding, structure details
- **Entries**: individual data blocks with headers and content
- **Readable text**: control characters displayed as `\x01`, `\x02`, etc.
- **Line arrays**: content split into manageable lines instead of long strings

## Testing Status

Currently tested with **book files** from Trails games. Other `._dt` file types may work but haven't been extensively tested yet.

## Requirements

- Python 3.6+
- No external dependencies