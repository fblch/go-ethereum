# Linux ARM64 向け el-stack 組み込み手順

<!-- AWAIISHIMA.md の linux_arm64 向け手順を移行した文書です。 -->

## 概要

Linux AMD64 のホスト環境で Linux ARM64 向け el-stack のスタティックライブラリをクロスビルドし、geth に組み込む手順を示す。

最終更新日: 2026/08/19

## 動作確認環境

この手順の作成者が確認に使用したホスト環境は次のとおり。クロスビルドはホスト、ターゲット、GNU ツールチェーンの組み合わせによって結果が変わり得るため、問題の再現や差分の切り分けに使用する。

- CPU アーキテクチャ: x86_64（AMD64）
- OS: Windows 11 Pro 25H2（OS ビルド 26200.8457）上の WSL2
- WSL ディストリビューション: Ubuntu 24.04
- ターゲットアーキテクチャ: Linux ARM64

## 前提条件

el-stack は Rust で記述されているため、ビルド前に Rust を利用できる状態にしておく。

### クロスコンパイルツールのインストール

Linux AMD64 ホスト上で ARM64 用コードを生成し、ARM64 用の C ランタイムへリンクするため、AArch64 GNU コンパイラ、binutils、クロス開発用 glibc をインストールする。`apt update` は、インストール前に Ubuntu のパッケージ情報を最新化するために実行する。

```bash
sudo apt update
sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-dev-arm64-cross
```

### Rust target の追加

Rust コードを Linux ARM64 向けにコンパイルする際に必要な標準ライブラリを導入するため、ターゲット `aarch64-unknown-linux-gnu` を Rust ツールチェーンへ追加する。

```bash
rustup target add aarch64-unknown-linux-gnu
```

## el-stack のソース取得

ビルド対象の Rust ソースと Cargo の依存関係定義を取得するため、el-stack のリポジトリをクローンし、作業ディレクトリへ移動する。

```bash
git clone https://github.com/freebit-rd/el-stack-rs.git
cd el-stack-rs
```

## el-stack のビルド

### クロスコンパイル用環境変数の設定

Cargo および依存クレートのビルドスクリプトが、ホスト用ツールではなく Linux ARM64 用の GNU ツールを使用するように設定する。

- `CC_aarch64_unknown_linux_gnu`: C/C++ ソースを Linux ARM64 向けにコンパイルするコンパイラを指定する。
- `AR_aarch64_unknown_linux_gnu`: ARM64 用のオブジェクトファイルをスタティックライブラリへまとめるツールを指定する。
- `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER`: Cargo が Linux ARM64 用成果物のリンクに使用するリンカーを明示する。

```bash
export CC_aarch64_unknown_linux_gnu="aarch64-linux-gnu-gcc"
export AR_aarch64_unknown_linux_gnu="aarch64-linux-gnu-ar"
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="aarch64-linux-gnu-gcc"
```

### ライブラリのビルド

`el-stack` パッケージだけを、Cargo feature `loginit` を有効にしたリリース構成で Linux ARM64 向けにビルドする。`--target` を省略するとホストの Linux AMD64 向けにビルドされるため、明示が必要である。`loginit` の具体的な役割と必要性は el-stack 側の定義に依存するため、採用するコミットの `Cargo.toml` も確認すること。

```bash
cargo build --package el-stack --features loginit --release --target aarch64-unknown-linux-gnu
```

## 生成物の確認

成果物の想定出力先は次のとおり。Cargo はターゲットとビルド構成ごとに出力先を分けるため、このパスを確認することで、ホスト用やデバッグ用のライブラリを誤って使用することを防げる。

```text
el-stack-rs/target/aarch64-unknown-linux-gnu/release/libel_stack.a
```

## geth への配置

ビルドで生成したスタティックライブラリを geth 側へ配置し、cgo がリポジトリ内の安定した相対パスからリンクできる状態にする。OS とアーキテクチャ別のディレクトリへ分けることで、他のターゲット向けライブラリとの取り違えを防ぐ。

採用している el-stack のバージョンを判別し、Go 側のリンク指定との対応を確認できるよう、配置するファイル名にバージョンを含めること。

配置先は次のとおり。`<version_number>` は採用する el-stack のバージョン番号へ置き換える。

例: el-stack version 1.0.0を利用する場合  
`libel_stack_v1.0.0.a`

```text
go-ethereum/p2p/elstack/el_stack/libs/linux_arm64/libel_stack_<version_number>.a
```

## geth のビルドとリンク確認

`go-ethereum/p2p/elstack/el_stack/el_stack.go` の次の記述を、配置したライブラリのファイル名と一致させる。cgo の `!android,linux,arm64` 条件により、Android を除く Linux ARM64 ビルド時だけこのライブラリが選択される。`${SRCDIR}` は実行時のカレントディレクトリに依存しない参照を可能にし、`-lm` はネイティブコードが使用する数学ライブラリをリンクする。

```go
// #cgo !android,linux,arm64 LDFLAGS: ${SRCDIR}/libs/linux_arm64/libel_stack_<version_number>.a -lm
```

`go-ethereum` ディレクトリへ移動し、次のコマンドで Linux ARM64 向け geth をクロスビルドする。`-arch arm64` は Go のターゲットアーキテクチャを、`-cc` は cgo が使用する ARM64 用 C コンパイラを指定し、Go と Rust の両方を同じターゲットへそろえる。

```bash
go run build/ci.go install -arch arm64 -cc aarch64-linux-gnu-gcc
```

エラーが発生せずにコマンドが終了すれば、Go コードと ARM64 用 Rust スタティックライブラリのコンパイルおよびリンクは成功である。
