# Android ARM64 向け el-stack 組み込み手順

<!-- AWAIISHIMA.md の android_arm64 向け手順を移行した文書です。 -->

## 概要

Linux AMD64 のホスト環境で Android ARM64 向け el-stack のスタティックライブラリをクロスビルドし、cgo を通して geth に組み込む手順を示す。

最終更新日: 2026/08/19

## 動作確認環境

この手順の作成者が確認に使用した環境は次のとおり。クロスビルドはホスト OS、NDK、ターゲット API の組み合わせによって結果が変わり得るため、問題の再現や差分の切り分けに使用する。

- CPU アーキテクチャ: x86_64（AMD64）
- OS: Windows 11 Pro 25H2（OS ビルド 26200.8457）上の WSL2
- WSL ディストリビューション: Ubuntu 24.04
- Android SDK Platform: API レベル 36（36.0.0および36.1.0）
- Android NDK: 28.1.13356709（r28b）
- ターゲット ABI: Android ARM64

## 前提条件

el-stack は Rust で記述されているため、ビルド前に Rust を利用できる状態にしておく。

TheChainApp のビルドで使用しているものと同じ Android SDK および NDK を用意する。この手順では、Windows 側の SDK/NDK を WSL2 から参照せず、Ubuntu 側へインストールする。

### Linux 側へツールチェーンを用意する理由

この手順ではビルドコマンドを WSL2 上の Ubuntu で実行するため、NDK に含まれる `clang`、`llvm-ar`、`llvm-ranlib` などには Linux AMD64 ホスト向けの実行ファイルが必要となる。生成物のターゲットは Android ARM64 だが、クロスコンパイラ自体はビルドを実行するホスト OS 上で動作するため、ターゲット用のアーキテクチャとツールチェーンを実行する環境は別に考える必要がある。

Windows 用 NDK のツールチェーンは Windows ホスト向けであり、この文書で指定する `toolchains/llvm/prebuilt/linux-x86_64/bin` のツールとは実行形式や配置が異なる。WSL2 から Windows 側の SDK/NDK を参照すると、Cargo やビルドスクリプトが Linux 用ツールを検出できないほか、Windows と Linux のパス表現、ファイル権限、シンボリックリンクなどの差異が問題になる可能性がある。そのため、ビルド環境を Ubuntu 内で完結させ、使用する NDK のバージョンだけを TheChainApp 側とそろえる構成としている。

### 必要パッケージのインストール

Android SDK の取得と展開、および SDK 管理ツールの実行に必要なパッケージをインストールする。`wget` はアーカイブの取得、`unzip` は展開、JDK は Java で実装された Android SDK Command-line Tools の実行に使用する。`apt update` は、インストール前に Ubuntu のパッケージ情報を最新化するために実行する。

```bash
sudo apt update
sudo apt install -y wget unzip openjdk-17-jdk
```

### Android SDK Command-line Tools の配置

SDK、Platform、NDK を同じ仕組みで取得・管理するため、Google が提供する Command-line Tools を配置する。`cmdline-tools/latest` というディレクトリ構成にそろえることで、後続の `PATH` 設定から `sdkmanager` を一意に参照できる。

```bash
mkdir -p ~/Android/Sdk
cd ~/Android
wget https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip commandlinetools-linux-*_latest.zip
mkdir -p ~/Android/Sdk/cmdline-tools
mv cmdline-tools ~/Android/Sdk/cmdline-tools/latest
```

### SDK の環境変数設定

`ANDROID_HOME` は Android SDK の配置先をビルドツールへ通知するために設定する。Command-line Tools を `PATH` に加えることで `sdkmanager` をフルパスなしで実行できる。`platform-tools` と `emulator` は本手順の el-stack ビルドでは直接使用しないが、後続の Android アプリの配置や動作確認で `adb` などを使用できるようにしている。

次の設定を `~/.bashrc` へ追加し、新しいシェルでも有効になるようにする。最後に `source` を実行し、現在のシェルにも設定を反映する。

```bash
echo 'export ANDROID_HOME=$HOME/Android/Sdk' >> ~/.bashrc
echo 'export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$PATH' >> ~/.bashrc
echo 'export PATH=$ANDROID_HOME/platform-tools:$PATH' >> ~/.bashrc
echo 'export PATH=$ANDROID_HOME/emulator:$PATH' >> ~/.bashrc
source ~/.bashrc
```

`sdkmanager` が実行できることを確認する。ここでバージョンが表示されれば、Command-line Tools の配置、JDK、および `PATH` の設定を後続のパッケージ取得前に検証できる。

```bash
sdkmanager --version
```

### SDK ライセンスへの同意

SDK Platform や NDK のインストールにはライセンスへの同意が必要であるため、先に未同意のライセンスを確認して受諾する。これにより、後続の `sdkmanager` がライセンス未同意で中断することを防ぐ。

```bash
yes | sdkmanager --licenses
```

### Android SDK Platform のインストール

TheChainApp と同じ Android API に対して geth の AAR を組み込み、アプリ側との環境差を減らすため、動作確認に使用した SDK Platform をインストールする。SDK Platform は主に Android アプリおよび AAR のビルドで参照され、Rust のスタティックライブラリ単体のクロスビルドには NDK を使用する。

Android Platform 36.0.0をインストールする。

```bash
sdkmanager "platforms;android-36"
```

拡張 API を使用する構成にも合わせられるよう、Android Platform 36.1.0に相当する extension level 1 もインストールする。

```bash
sdkmanager "platforms;android-36-ext1"
```

### Android NDK のインストール

NDK には Android ARM64 向けの Clang、LLVM のアーカイブツール、Android のヘッダーおよびシステムライブラリが含まれる。Rust の依存クレートに C/C++ コードが含まれる場合や、最終的なスタティックライブラリを Android 向けにリンクする場合に必要となる。TheChainApp と同じ r28b に固定し、ツールチェーンや ABI の差による不整合を避ける。

```bash
sdkmanager "ndk;28.1.13356709"
```

頻繁に Android 向けビルドを行う場合は、任意で NDK の環境変数も `~/.bashrc` に追加する。`ANDROID_NDK_HOME` を固定しておくと、ビルドスクリプトから使用する NDK の場所とバージョンを明示できる。Linux 用ツールチェーンの `bin` ディレクトリを `PATH` に加えることで、LLVM の各ツールもフルパスなしで実行できる。

```bash
echo 'export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/28.1.13356709' >> ~/.bashrc
echo 'export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

### Rust target の追加

Rust コードを Android ARM64 向けにコンパイルする際に必要な標準ライブラリを導入するため、ターゲット `aarch64-linux-android` を Rust ツールチェーンへ追加する。この名前の `linux` は Android が Linux カーネル系のターゲットであることを表し、ホスト OS 用の Linux バイナリを生成する指定ではない。

```bash
rustup target add aarch64-linux-android
```

## el-stack のソース取得

ビルド対象の Rust ソースと Cargo の依存関係定義を取得するため、el-stack のリポジトリをクローンし、作業ディレクトリへ移動する。

```bash
git clone https://github.com/freebit-rd/el-stack-rs.git
cd el-stack-rs
```

## el-stack のビルド

### NDK とツールチェーンの環境変数設定

後続の設定で同じ絶対パスを繰り返さず、意図した NDK r28b の Linux AMD64 用ツールを確実に選択するため、NDK ルートとツールチェーンの `bin` ディレクトリを環境変数へ設定する。ここでの `linux-x86_64` はツールを実行するホストを表し、生成物のターゲットは後続で Android ARM64 に指定する。

```bash
export ANDROID_NDK_HOME="$HOME/Android/Sdk/ndk/28.1.13356709"
export NDK_ROOT="$ANDROID_NDK_HOME"
export TOOLCHAIN_BIN="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin"
```

### Android向けクロスコンパイル環境変数の設定

Cargo および依存クレートのビルドスクリプトが、ホスト用の GCC/Clang ではなく Android ARM64 用のツールを使用するように設定する。

- `CC_aarch64_linux_android`: C/C++ ソースのコンパイラを Android ARM64、API レベル21向け Clang にする。API レベル21は、このリポジトリの `make android` が NDK r28 の最小サポート API に合わせて指定している値と一致する。
- `AR_aarch64_linux_android`: Android ARM64 用のオブジェクトファイルをスタティックライブラリへまとめるツールを指定する。
- `RANLIB_aarch64_linux_android` および `RANLIB`: スタティックライブラリのシンボル索引を生成する LLVM ツールをターゲット固有設定と汎用設定の両方へ指定する。
- `CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER`: Cargo が Android ARM64 用成果物のリンクに使用するリンカーを明示する。

```bash
export CC_aarch64_linux_android="$TOOLCHAIN_BIN/aarch64-linux-android21-clang"
export AR_aarch64_linux_android="$TOOLCHAIN_BIN/llvm-ar"
export RANLIB_aarch64_linux_android="$TOOLCHAIN_BIN/llvm-ranlib"
export RANLIB="$RANLIB_aarch64_linux_android"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
```

### ライブラリのビルド

`el_stack` パッケージだけを、最適化を有効にしたリリース構成で Android ARM64 向けにビルドする。`--target` を省略するとホストの Linux AMD64 向けにビルドされるため、明示が必要である。

```bash
cargo build \
    --package "el_stack" \
    --release \
    --target aarch64-linux-android
```

## 生成物の確認

生成物は `target/aarch64-linux-android/release` に出力される。Cargo はターゲットとビルド構成ごとに出力先を分けるため、このディレクトリを確認することで、ホスト用やデバッグ用のライブラリを誤って使用することを防げる。

## geth への配置

ビルドで生成したスタティックライブラリを geth 側へ配置し、cgo がリポジトリ内の安定した相対パスからリンクできる状態にする。OS とアーキテクチャ別のディレクトリへ分けることで、他のプラットフォーム向けライブラリとの取り違えを防ぐ。

また、採用している el-stack のバージョンを判別し、Go 側のリンク指定との対応を確認できるよう、配置するファイル名にバージョンを含めること。

配置先は次のとおり。`<version_number>` は採用する el-stack のバージョン番号へ置き換える。

例: el-stack version 1.0.0を利用する場合  
`libel_stack_v1.0.0.a`

```text
go-ethereum/p2p/elstack/el_stack/libs/android_arm64/libel_stack_<version_number>.a
```

## geth のビルドとリンク確認

`go-ethereum/p2p/elstack/el_stack/el_stack.go` の次の記述を、配置したライブラリのファイル名と一致させる。cgo の `android,arm64` 条件により、このライブラリは Android ARM64 ビルド時だけリンクされる。`${SRCDIR}` を基準にすることで実行時のカレントディレクトリに依存せずライブラリを参照でき、`-lm` はネイティブコードが使用する Android の数学ライブラリをリンクする。

```go
// #cgo android,arm64 LDFLAGS: ${SRCDIR}/libs/android_arm64/libel_stack_<version_number>.a -lm
```

`go-ethereum` ディレクトリへ移動し、Android ARM64 向け geth をビルドする。この処理によって Go、cgo、および配置した Rust スタティックライブラリをまとめてリンクできることを確認する。Android 向け geth のビルド手順は本ドキュメントでは詳細に記さない。

```bash
make android
```

エラーが発生せずにコマンドが終了し、`go-ethereum/build/bin/geth.aar` と `go-ethereum/build/bin/geth-sources.jar` が生成されれば、ネイティブライブラリのリンクと Android 向けパッケージングまで完了したと判断できる。AAR は TheChainApp へ組み込むバイナリ、sources JAR は対応するソースを提供する成果物である。
