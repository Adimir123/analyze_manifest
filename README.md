# Android Manifest Analyzer 🔍

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A powerful tool for analyzing Android manifest files, identifying security vulnerabilities, and extracting deep links with colorful console output.

## Features ✨

- **Comprehensive Analysis** of AndroidManifest.xml
- **Security Vulnerability Detection** (exported components, dangerous permissions)
- **Deep Link Extraction** with URI schemes
- **Permission Analysis** with risk categorization
- **Colorful Console Output** for better readability
- **JSON Export** option for programmatic use
- **String Resource Resolution** (@string/ references)

## Installation ⚙️

```bash
git clone https://github.com/yourusername/android-manifest-analyzer.git
cd android-manifest-analyzer
```

## Usage 🚀

### Basic Analysis
```bash
python3 analyze_manifest.py -m AndroidManifest.xml
```

### With String Resources
```bash
python3 analyze_manifest.py -m AndroidManifest.xml -s res/values/strings.xml
```

### JSON Output
```bash
python3 analyze_manifest.py -m AndroidManifest.xml -f json
```

## Command Line Options 🔧

| Option | Description | Default |
|--------|-------------|---------|
| `-m`, `--manifest` | Path to AndroidManifest.xml | **Required** |
| `-s`, `--strings` | Path to strings.xml | `res/values/strings.xml` |
| `-f`, `--format` | Output format (`text` or `json`) | `text` |

## Color Coding 🎨

| Color | Meaning |
|-------|---------|
| 🔴 Red | High risk vulnerabilities |
| 🟡 Yellow | Warnings/medium risk |
| 🟢 Green | Safe components |
| 🔵 Blue | Informational items |
| 🟠 Orange | Activities |
| 💙 Light Blue | Services |
| 💚 Light Green | Receivers |
| 💖 Pink | Content Providers |

## Requirements 📦

- Python 3.6+
- BeautifulSoup4 (`pip install beautifulsoup4`)

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing 🤝

Pull requests are welcome! Please open an issue first to discuss what you'd like to change.

---
