# iOS Deb Analyzer

iOS .deb 패키지 및 dylib 바이너리를 분석하는 Python 도구입니다.

## Features

- .deb 패키지 파싱 (메타데이터, 파일 목록)
- Mach-O dylib 바이너리 분석
- Objective-C 클래스/메서드 추출
- 후킹된 메서드 탐지 (logos, MSHookMessageEx)
- 심볼 및 문자열 추출
- GUI 및 CLI 인터페이스

## Installation

```bash
pip install -e .
```

## Usage

### GUI
```bash
python -m ios_deb_analyzer.gui
```

### CLI
```bash
# Analyze deb package
ios-deb-analyzer analyze package.deb

# Analyze dylib directly
ios-deb-analyzer analyze tweak.dylib --dylib-only

# Export to JSON
ios-deb-analyzer analyze package.deb --json --output report.json
```

## Requirements

- Python 3.10+
- LIEF
- PyQt6
- click
- rich

## Note

Objective-C 메타데이터 추출을 위해서는 LIEF Extended 버전이 필요합니다.
https://lief.re/doc/latest/extended/intro.html
