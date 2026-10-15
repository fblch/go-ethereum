# Linux AMD64 向け el-stack 組み込み手順

<!-- AWAIISHIMA.md の linux_amd64 向け手順を移行した文書です。 -->

## 概要

Linux AMD64 向けに el-stack のスタティックライブラリをビルドし、geth に組み込む手順を示す。

最終更新日: 2026/08/19

## 動作確認環境

この手順の作成者が確認に使用した環境は次のとおり。ネイティブビルドでも OS、Rust、C コンパイラの違いが結果に影響し得るため、問題の再現や差分の切り分けに使用する。

- CPU アーキテクチャ: x86_64（AMD64）
- OS: Windows 11 Pro 25H2（OS ビルド 26200.8457）上の WSL2
- WSL ディストリビューション: Ubuntu 24.04

## 前提条件

el-stack は Rust で記述されているため、ビルド前に Rust を利用できる状態にしておく。

ホストとターゲットがともに Linux AMD64 であるため、別アーキテクチャ向けのクロスコンパイラや Rust target の追加は必要ない。ただし、Rust の依存クレートがネイティブコードを含む場合に備え、通常の C コンパイラを利用できる状態にしておく。

## el-stack のソース取得

ビルド対象の Rust ソースと Cargo の依存関係定義を取得するため、el-stack のリポジトリをクローンし、作業ディレクトリへ移動する。

```bash
git clone https://github.com/freebit-rd/el-stack-rs.git
cd el-stack-rs
```

## el-stack のビルド

el-stack リポジトリが Linux 向けに用意しているビルド設定を使用するため、リポジトリのルートで生成スクリプトを実行する。スクリプト内部の処理は採用する el-stack のバージョンに依存するため、実行前に内容も確認すること。

```bash
./generate_go.sh
```

## 生成物の確認

成果物の想定出力先は次のとおり。`release` ディレクトリを確認することで、デバッグ構成のライブラリを誤って使用することを防げる。

```text
el-stack-rs/target/release/libel_stack.a
```

## geth への配置

ビルドで生成したスタティックライブラリを geth 側へ配置し、cgo がリポジトリ内の安定した相対パスからリンクできる状態にする。OS とアーキテクチャ別のディレクトリへ分けることで、他のターゲット向けライブラリとの取り違えを防ぐ。

採用している el-stack のバージョンを判別し、Go 側のリンク指定との対応を確認できるよう、ファイル名にバージョンを含めること。

例: el-stack version 1.0.0を利用する場合  
`libel_stack_v1.0.0.a`

配置先:

```text
go-ethereum/p2p/elstack/el_stack/libs/linux_amd64/libel_stack_<version_number>.a
```

## geth のビルドとリンク確認

`go-ethereum/p2p/elstack/el_stack/el_stack.go` の次の記述を、配置したライブラリのファイル名と一致させる。cgo の `!android,linux,amd64` 条件により、Android を除く Linux AMD64 ビルド時だけこのライブラリが選択される。`${SRCDIR}` は実行時のカレントディレクトリに依存しない参照を可能にし、`-lm` はネイティブコードが使用する数学ライブラリをリンクする。

```go
// #cgo !android,linux,amd64 LDFLAGS: ${SRCDIR}/libs/linux_amd64/libel_stack_<version_number>.a -lm
```

`go-ethereum` ディレクトリへ移動し、通常の Linux AMD64 ビルドを実行する。この処理により、Go コードと配置した Rust スタティックライブラリを cgo 経由でまとめてリンクできることを確認する。

```bash
make all
```

エラーが発生せずにコマンドが終了すれば、コンパイルとリンクは成功である。
