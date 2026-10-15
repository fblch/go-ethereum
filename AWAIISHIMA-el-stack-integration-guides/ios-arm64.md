# iOS / iOS Simulator ARM64 向け el-stack 組み込み手順

<!-- Linux AMD64 向け手順を基に、iOS実機およびiOS Simulator ARM64向けの情報へ置き換えた文書です。 -->

## 概要

macOS のホスト環境で、iOS ARM64 実機およびiOS Simulator ARM64向け el-stack のスタティックライブラリをビルドし、geth に組み込む手順を示す。

geth のiOS向けビルドでは、iOS実機向けとiOS Simulator向けのビルドが同時に実行されるため、両ターゲットの手順をこの文書でまとめて扱う。同じ ARM64 でも実機用と Simulator 用では対象プラットフォームが異なり、スタティックライブラリを共用できないため、両方の成果物を個別に用意する必要がある。

最終更新日: 2026/08/19

## 動作確認環境

この手順の作成者が確認に使用したホスト環境は次のとおり。Xcode、各 Apple SDK、Rust target、Deployment Target の組み合わせによって結果が変わり得るため、問題の再現や差分の切り分けに使用する。

- CPU アーキテクチャ: ARM64
- OS: macOS Sequoia 15.4.1
- ターゲット:
  - iOS ARM64 実機
  - iOS Simulator ARM64

## 前提条件

el-stack は Rust で記述されているため、ビルド前に Rust を利用できる状態にしておく。

iOS 向けフレームワークのコンパイル、リンク、およびパッケージングに Apple のツールチェーンが必要となるため、Xcode、iOS SDK、iOS Simulator SDK を利用できる状態にしておく。

Rust コードをiOS実機とiOS Simulator向けにコンパイルする際に必要な標準ライブラリを導入するため、両方の Rust target を追加する。

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

## el-stack のソース取得

ビルド対象の Rust ソースと Cargo の依存関係定義を取得するため、el-stack のリポジトリをクローンし、作業ディレクトリへ移動する。

```bash
git clone https://github.com/freebit-rd/el-stack-rs.git
cd el-stack-rs
```

## el-stack のビルド

el-stack リポジトリがiOS実機用とiOS Simulator用に用意しているビルド設定をまとめて適用するため、リポジトリのルートで生成スクリプトを実行する。スクリプト内部の処理は採用する el-stack のバージョンに依存するため、実行前に内容も確認すること。

```bash
./generate_ios.sh
```

## 生成物の確認

各成果物の出力先は次のとおり。ターゲット別のディレクトリを確認することで、同じ ARM64 であってもiOS実機用とiOS Simulator用のライブラリを取り違えることを防げる。

```text
iOS実機:       el-stack-rs/target/aarch64-apple-ios/release/libel_stack.a
iOS Simulator: el-stack-rs/target/aarch64-apple-ios-sim/release/libel_stack.a
```

## geth への配置

ビルドで生成した2つのスタティックライブラリを geth 側へ配置し、cgo がリポジトリ内の安定した相対パスから選択できる状態にする。実機用と Simulator 用のディレクトリへ分けることで、対象プラットフォームが異なるライブラリの取り違えを防ぐ。

採用している el-stack のバージョンを判別し、Go 側のリンク指定との対応を確認できるよう、配置するファイル名にバージョンを含めること。

配置先はターゲットごとに次のとおり。`<version_number>` は採用する el-stack のバージョン番号へ置き換える。

例: el-stack version 1.0.0を利用する場合  
`libel_stack_v1.0.0.a`

iOS ARM64実機向け:

```text
go-ethereum/p2p/elstack/el_stack/libs/ios_arm64/libel_stack_<version_number>.a
```

iOS Simulator ARM64向け:

```text
go-ethereum/p2p/elstack/el_stack/libs/iossimulator_arm64/libel_stack_<version_number>.a
```

## geth のビルドとリンク確認

`go-ethereum/p2p/elstack/el_stack/el_stack.go` にあるiOS実機用とiOS Simulator用の記述を、それぞれ配置したライブラリのファイル名と一致させる。cgo の `ios,arm64` と `iossimulator,arm64` の条件が、ビルド対象に応じて対応するライブラリを選択する。`${SRCDIR}` は実行時のカレントディレクトリに依存しない参照を可能にし、`-lm` はネイティブコードが使用する数学ライブラリをリンクする。

```go
// #cgo ios,arm64 LDFLAGS: ${SRCDIR}/libs/ios_arm64/libel_stack_<version_number>.a -lm
// #cgo iossimulator,arm64 LDFLAGS: ${SRCDIR}/libs/iossimulator_arm64/libel_stack_<version_number>.a -lm
```

`go-ethereum` ディレクトリへ移動し、次のコマンドでiOS実機およびiOS Simulator向けフレームワークを同時にビルドする。この処理により、Go、cgo、および両ターゲット用の Rust スタティックライブラリをまとめてリンクできることを確認する。

```bash
make ios
```

エラーが発生せずにコマンドが終了し、`go-ethereum/build/bin/Geth.framework` が生成されれば、ネイティブライブラリのリンクとiOS向けフレームワークの生成まで完了したと判断できる。

実際にiOSアプリへ組み込む場合の手順は、本ドキュメントの対象外とする。
