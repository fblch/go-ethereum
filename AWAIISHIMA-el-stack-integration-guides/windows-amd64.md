# Windows AMD64 向け el-stack 組み込み手順

<!-- AWAIISHIMA.md の windows_amd64 向け手順を移行した文書です。 -->

## 概要

Windows AMD64 向けに el-stack のスタティックライブラリを GNU ツールチェーンでビルドし、geth に組み込む手順を示す。

最終更新日: 2026/08/19

## 動作確認環境

この手順の作成者が確認に使用した環境は次のとおり。Windows 上では MSVC と GNU で ABI やツールが異なるため、Rust target、シェル、GNU ツールチェーンの組み合わせを問題の再現や差分の切り分けに使用する。

- CPU アーキテクチャ: x86_64（AMD64）
- OS: Windows 11 Pro 25H2
- OS ビルド: 26200.8457
- 操作シェル: PowerShellおよびMSYS2 UCRT64
- ターゲット: `x86_64-pc-windows-gnu`

## 前提条件

el-stack は Rust で記述されているため、ビルド前に Rust を利用できる状態にしておく。

### MSYS2 の確認

この手順では Rust の `x86_64-pc-windows-gnu` ターゲットと cgo のリンクに GNU ツールを使用するため、MSYS2 がインストール済みであることを確認する。標準的なインストール先は `C:\msys64` である。

PowerShellで次のコマンドを実行し、MSYS2 UCRT64 の GNU ツールチェーンに必要な実行ファイルがあることを確認する。`gcc` はコンパイルとリンク、`ar` はスタティックライブラリの作成、`dlltool` は Windows DLL のインポートライブラリ処理に使用される。

```powershell
Test-Path C:\msys64\ucrt64\bin\gcc.exe
Test-Path C:\msys64\ucrt64\bin\ar.exe
Test-Path C:\msys64\ucrt64\bin\dlltool.exe
```

### MSYS2 の更新

パッケージデータベース、基本システム、およびインストール済みパッケージを整合した状態にするため、MSYS2 UCRT64 シェルでシステム全体を更新する。

```bash
pacman -Syu
```

MSYS2 の中核コンポーネントが更新された場合は実行中のシェルへ反映できないため、指示に従ってMSYS2を再起動し、残りの更新を続行する。

```bash
pacman -Su
```

### GNU ツールチェーンのインストール

Windows AMD64 用の GCC と binutils をそろえるため、MSYS2 UCRT64 シェルで次のコマンドを実行する。`--needed` は、導入済みで最新のパッケージを不要に再インストールしないための指定である。

```bash
pacman -S --needed mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-binutils
```

### Rust target の追加

Rust コードを Windows AMD64 の GNU ABI 向けにコンパイルする際に必要な標準ライブラリを導入するため、PowerShellで Rust target を追加する。

```powershell
rustup target add x86_64-pc-windows-gnu
```

## el-stack のソース取得

ビルド対象の Rust ソースと Cargo の依存関係定義を取得するため、el-stack のリポジトリをクローンする。

```powershell
git clone https://github.com/freebit-rd/el-stack-rs.git
```

PowerShellで、Cargo の設定ファイルとソースがある作業ディレクトリへ移動する。`<ユーザー名>` は実際のWindowsユーザー名へ置き換える。

```powershell
Set-Location C:\Users\<ユーザー名>\el-stack-rs
```

## el-stack のビルド

### GNU ツールチェーンをPATHへ追加

PowerShellから MSYS2 UCRT64 の GNU ツールを名前で実行できるよう、現在のプロセスの `PATH` の先頭へ追加する。先頭に置くことで、別のディレクトリに同名ツールがある場合も、この手順で確認したツールチェーンを優先する。

```powershell
$env:PATH = "C:\msys64\ucrt64\bin;$env:PATH"
```

### ビルド用環境変数の設定

Cargo および依存クレートのビルドスクリプトが、意図した GNU ツールを使用するように設定する。`CC` は C/C++ ソースのコンパイラ、`AR` はスタティックライブラリ作成ツール、`CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER` は対象 Rust target のリンカーを指定する。

```powershell
$env:CC = "gcc"
$env:AR = "ar"
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "gcc"
```

### ツールの確認

実際に名前解決されるツールのパスを確認し、MSYS2 の別環境や他の GNU ツールチェーンが誤って選択されていないことをビルド前に検証する。

```powershell
where.exe gcc
where.exe ar
where.exe dlltool
```

期待される出力例は次のとおり。

```text
C:\msys64\ucrt64\bin\gcc.exe
C:\msys64\ucrt64\bin\ar.exe
C:\msys64\ucrt64\bin\dlltool.exe
```

### ライブラリのビルド

`el-stack` パッケージだけを、Cargo feature `loginit` を有効にしたリリース構成で Windows AMD64 の GNU ABI 向けにビルドする。`--target` を明示することで、既定の Rust target が MSVC の環境でも GNU 向け成果物を生成する。`loginit` の具体的な役割と必要性は el-stack 側の定義に依存するため、採用するコミットの `Cargo.toml` も確認すること。

```powershell
cargo build --package el-stack --features loginit --release --target x86_64-pc-windows-gnu
```

## 生成物の確認

次のコマンドで、GNU target のリリース用ディレクトリにスタティックライブラリが生成されたことを確認する。これにより、MSVC 向けやデバッグ用の成果物を誤って使用することを防げる。ファイルエクスプローラーから直接確認してもよい。

```powershell
Get-ChildItem .\target\x86_64-pc-windows-gnu\release\libel_stack.a
```

## geth への配置

ビルドで生成したスタティックライブラリを geth 側へ配置し、cgo がリポジトリ内の安定した相対パスからリンクできる状態にする。OS とアーキテクチャ別のディレクトリへ分けることで、他のターゲット向けライブラリとの取り違えを防ぐ。

採用している el-stack のバージョンを判別し、Go 側のリンク指定との対応を確認できるよう、配置するファイル名にバージョンを含めること。

配置先は次のとおり。`<version_number>` は採用する el-stack のバージョン番号へ置き換える。

例: el-stack version 1.0.0を利用する場合  
`libel_stack_v1.0.0.a`

```text
go-ethereum/p2p/elstack/el_stack/libs/windows_amd64/libel_stack_<version_number>.a
```

## geth のビルドとリンク確認

`go-ethereum/p2p/elstack/el_stack/el_stack.go` の次の記述を、配置したライブラリのファイル名と一致させる。cgo の `windows,amd64` 条件により、Windows AMD64 ビルド時だけこのライブラリが選択される。`${SRCDIR}` は実行時のカレントディレクトリに依存しない参照を可能にする。`-lm` と各 Windows システムライブラリは、el-stack およびそのネイティブ依存関係が使用する数学、ネットワーク、ユーザー環境、低レベル NT API のシンボルを解決するためにリンクする。

```go
// #cgo windows,amd64 LDFLAGS: ${SRCDIR}/libs/windows_amd64/libel_stack_<version_number>.a -lm -liphlpapi -luserenv -lntdll
```

`go-ethereum` ディレクトリへ移動した PowerShell で、次のコマンドを実行してホストの Windows AMD64 向け geth をビルドする。この処理により、Go、cgo、GNU リンカー、および配置した Rust スタティックライブラリを組み合わせてリンクできることを確認する。

```powershell
go run build/ci.go install
```

エラーが発生せずにコマンドが終了すれば、コンパイルとリンクは成功である。
