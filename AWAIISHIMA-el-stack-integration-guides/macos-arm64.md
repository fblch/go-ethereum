# macOS ARM64 向け el-stack 組み込み手順

<!-- Linux AMD64 向け手順を基に、macOS ARM64 向けの情報へ置き換えた文書です。 -->

## 概要

Apple Silicon を搭載した macOS ARM64 向けに el-stack のスタティックライブラリをビルドし、geth に組み込む手順を示す。

最終更新日: 2026/08/19

## 動作確認環境

この手順の作成者が確認に使用した環境は次のとおり。macOS と Apple SDK、Rust、C コンパイラの組み合わせによって結果が変わり得るため、問題の再現や差分の切り分けに使用する。

- CPU アーキテクチャ: ARM64
- OS: macOS Sequoia 15.4.1

## 前提条件

el-stack は Rust で記述されているため、ビルド前に Rust を利用できる状態にしておく。

Rust や cgo から Apple のリンカーとシステムフレームワークを利用できるよう、Xcode Command Line Tools も利用できる状態にしておく。ホストとターゲットがともに macOS ARM64 であるため、別アーキテクチャ向けのクロスコンパイラや Rust target の追加は必要ない。

## el-stack のソース取得

ビルド対象の Rust ソースと Cargo の依存関係定義を取得するため、el-stack のリポジトリをクローンし、作業ディレクトリへ移動する。

```bash
git clone https://github.com/freebit-rd/el-stack-rs.git
cd el-stack-rs
```

## el-stack のビルド

el-stack リポジトリが macOS 向けに用意しているビルド設定を使用するため、リポジトリのルートで生成スクリプトを実行する。スクリプト内部の処理は採用する el-stack のバージョンに依存するため、実行前に内容も確認すること。

```bash
./generate_macos.sh
```

## 生成物の確認

成果物の出力先は `el-stack-rs/target/aarch64-apple-darwin/release/libel_stack.a` である。ターゲット名と `release` ディレクトリを確認することで、別アーキテクチャ用やデバッグ用のライブラリを誤って使用することを防げる。

## geth への配置

ビルドで生成したスタティックライブラリを geth 側へ配置し、cgo がリポジトリ内の安定した相対パスからリンクできる状態にする。OS とアーキテクチャ別のディレクトリへ分けることで、他のターゲット向けライブラリとの取り違えを防ぐ。

採用している el-stack のバージョンを判別し、Go 側のリンク指定との対応を確認できるよう、配置するファイル名にバージョンを含めること。

配置先は次のとおり。`<version_number>` は採用する el-stack のバージョン番号へ置き換える。

例: el-stack version 1.0.0を利用する場合  
`libel_stack_v1.0.0.a`

```text
go-ethereum/p2p/elstack/el_stack/libs/darwin_arm64/libel_stack_<version_number>.a
```

## geth のビルドとリンク確認

`go-ethereum/p2p/elstack/el_stack/el_stack.go` の次の記述を、配置したライブラリのファイル名と一致させる。cgo の `darwin,arm64` 条件により、macOS ARM64 ビルド時だけこのライブラリが選択される。`${SRCDIR}` は実行時のカレントディレクトリに依存しない参照を可能にする。`-lm` と2つの Apple システムフレームワークは、el-stack およびそのネイティブ依存関係が使用する数学、システム構成、Core Foundation のシンボルを解決するためにリンクする。

```go
// #cgo darwin,arm64 LDFLAGS: ${SRCDIR}/libs/darwin_arm64/libel_stack_<version_number>.a -lm -framework SystemConfiguration -framework CoreFoundation
```

`go-ethereum` ディレクトリへ移動し、次のコマンドでホストの macOS ARM64 向け geth をビルドする。この処理により、Go コードと配置した Rust スタティックライブラリ、および必要な Apple フレームワークをまとめてリンクできることを確認する。

```bash
make all
```

エラーが発生せずにコマンドが終了すれば、コンパイルとリンクは成功である。
