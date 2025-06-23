# Game File Tools

Decompiler/compiler tools for `._dt` files from **Trails from Zero** and **Trails to Azure** games.

## Scripts

- **`dt_books.py`** - Book/story files
- **`dt_ittxt.py`** - Item files
- **`dt_town.py`** - Town file

## Usage

```bash
# Decompile to JSON
python dt_books.py file._dt
python dt_ittxt.py file._dt  
python dt_town.py file._dt

# Compile back to ._dt
python dt_books.py file.json
python dt_ittxt.py file.json
python dt_town.py file.json

# Test integrity after decompilation
python dt_books.py file._dt --test
```

## Output

Each tool creates JSON files with:
- Text content ready for translation
- File structure preservation
- Automatic encoding handling (Shift-JIS)

Edit the JSON and compile back to apply changes.

## Requirements

- Python 3.6+
- No external dependencies

## Community
Join our [Discord community](https://discord.com/invite/sGzmvFaFAe) for support and discussions about game modding and translations.
