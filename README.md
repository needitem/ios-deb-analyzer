# iOS Deb Analyzer

iOS .deb 패키지 및 dylib 바이너리를 분석하는 Python 도구입니다.

## Features

- .deb 패키지 파싱 (메타데이터, 파일 목록)
- Mach-O dylib 바이너리 분석
- Objective-C 클래스/메서드 추출 (커스텀 파서 내장)
- 후킹된 메서드 탐지 (logos, MSHookMessageEx)
- ARM64 디스어셈블리 (Capstone 기반)
- 심볼 및 문자열 추출
- GUI 및 CLI 인터페이스

## Download

[Releases](https://github.com/needitem/ios-deb-analyzer/releases)에서 실행 파일을 다운로드할 수 있습니다.

- `ios-deb-analyzer-gui.exe` - GUI 버전
- `ios-deb-analyzer-cli.exe` - CLI 버전

## Installation (개발용)

```bash
pip install -e .
```

## Usage

### GUI
```bash
# 실행 파일
ios-deb-analyzer-gui.exe

# 또는 Python
python -m ios_deb_analyzer.gui
```

GUI 기능:
- 드래그 앤 드롭으로 파일 분석
- ObjC 클래스/메서드 탭
- 후킹된 메서드 탭
- 라이브러리/심볼 탭
- 문자열 탭
- JSON 출력 탭
- 디스어셈블리 탭 (메서드 더블클릭)

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
- Capstone
- click
- rich

## Screenshots

### GUI
![GUI Screenshot](docs/gui.png)

## License

MIT
