# ベンダーコントローラー対応調査

この文書は、実 USB フラッシュ媒体について D1–D4 へ到達するための公開一次資料、実装済み範囲、認定されていない範囲を分離して記録する。

## 結論

2026-08-11 時点の実装と、repository に同梱していない実測 tuple を分ける。

| ファミリー | 厳密な読み取り専用識別 | service entry | 共通 recipe engine | 同梱 production tuple | nclr の扱い |
|---|---:|---:|---:|---:|---|
| Phison PS2251 family | version + NAND ID 実装済み | BootROM / 旧・後期 BtPram container 実装済み | 物理 erase、FBB/RBB、qualification、BBT/FTL/capacity、atomic commit、resume 実装済み | なし | exact recipe + loader + HIL が揃うまで C3 を拒否 |
| Alcor AU698x | config + flash ID 実装済み | runtime recipe | 同上 | なし | exact recipe + HIL が揃うまで C3 を拒否 |
| Silicon Motion SM32X | `F0 04 ... 02` identity page 実装済み | runtime recipe | 同上 | なし | exact erase/NAND/metadata recipe + HIL が揃うまで C3 を拒否 |
| SanDisk Cruzer proprietary (`82-00263-1` を含む) | exact USB/SCSI bootstrap + runtime `read-controller-id` / `read-nand-id` | runtime recipe | 同上 | なし | controller-owned 2 段 identity と exact recipe + HIL が揃うまで C3 を拒否 |
| USBest UT163 | 標準 INQUIRY の vendor-specific 領域の `U163` マーカー (追加 CDB なし) | 公開資料なし | なし | なし | 読み取り専用の識別のみ。service CDB が公開されていないため C3 を拒否 |

「MPTool で初期化できる」「コマンドが GOOD status を返す」「ファームウェアを書き換えられる」は、D1–D4 の処理証拠ではない。C3 を有効にするには、少なくとも全非 FBB ブロックの列挙、D1/D2 の物理消去、旧 RBB の個別消去結果、旧・新 BBT 差分、旧 FTL 世代の無効化、新 FTL の commit、電源再投入後の独立確認が必要である。

## 実装した安全境界

- USB VID は送信してよい読み取り専用プローブを 1 ファミリーへ限定するヒントとしてだけ使う。OEM VID を推測して総当たりしない。OEM VID は trusted production profile の exact USB / SCSI bootstrap が明示した family と runtime identity recipe でのみ扱う。
- VID からベンダー名・モデル名を表示するときは、ツール固有の表を持たず OS の usb.ids (linux-usb.org、udev hwdb の生成元) を読み、無い場合はデバイスの iManufacturer 文字列にフォールバックする。ベンダー名はブランド情報であり、コントローラ family の断定には使わない (例: Imation ブランドの UT163)。
- 読み取り専用の controller family 識別パラメータ (VID ヒント、INQUIRY マーカー、報告名) は `profiles/identify-*.toml` に置き、コードへ埋め込まない。ファミリ名は既知の enum と照合して検証する。
- Phison は vendor version page の `VR` シグネチャ、big-endian chip type、firmware bytes、run mode を検証する。続いて 6-byte NAND ID を取得し、全 `00` / 全 `FF` を拒否する。
- Alcor は 512-byte config の `99 07` シグネチャ、little-endian VID/PID/bcdDevice、USB string descriptor の型・偶数長・境界を検証する。シグネチャ確認後だけ flash ID を取得する。
- SCSI INQUIRY の vendor/product/revision 文字列を単独の controller 推定には使わない。署名済み production profile が USB VID/PID/bcdDevice と SCSI 3 文字列を全て固定した exact bootstrap tuple に限り、runtime recipe の候補選択へ使用する。
- 安全に送れる固定 identity CDB が公開されていない SanDisk Cruzer、後期 controller、OEM VID 製品では、exact USB VID / PID / bcdDevice と SCSI INQUIRY tuple を recipe artifact 選択に限って使う。この bootstrap は capability を有効化せず、runtime recipe の signed `read-controller-id` と `read-nand-id` が一致した後だけ実行可能にする。SanDisk では必須、Phison / Alcor / SMI では profile が明示した場合だけ使用する。
- production TOML だけでは実行 capability を公開しない。読み取り専用 plan probe は必要 runtime artifact を plan へ固定するだけである。run の再 probe で exact tuple に固定された runtime protocol recipe と必要な loader が認証され、controller response の exact identity が一致しなければならない。protocol trace と qualification report は profile の認定根拠として SHA-256 を固定する。
- コンパイル済み support は USB VID ではなく、署名検証済み controller response へ結び付ける。probe 失敗時や `unidentified` を名乗る profile は実行可能にならない。
- controller backend は core が同一 SCSI object から解決した `/dev/sgN` を必須とし、block fd と sysfs `device` が一致しなければ拒否する。
- 不明な vendor opcode、OEM VID に対するファミリー横断プローブ、Alcor `0x81` config write、Phison BootROM 遷移は通常の `probe` で送信しない。
- destructive recipe engine は CDB opcode を固定し、可変 field の byte 0 上書き、overlap、範囲外 transfer、署名のない status / commit response を拒否する。旧 RBB は消去後も再利用せず、FBB と preserve system range を target から除外する。
- BBT / FTL は inactive 固定長 image、exact checksum algorithm / coverage、prepare / commit marker、generation を recipe で明示し、activate 後に BBT state と commit generation を再読する。host response 消失時は commit state を先に照会する。
- service mode の USB reset は同一 physical USB path 上の唯一の whole device だけを再 bind し、2-slot SHA-256 controller state と fsync journal から再開する。

ヒントに使う `13fe`、`058f`、`090c`、`0781` は [USB-IF Company Vendor ID List](https://www.usb.org/sites/default/files/vendor_ids032322.pdf_1.pdf) の Phison Electronics Corp. `5118`、Alcor Micro Corp. `1423`、Silicon Motion Taiwan `2316`、SanDisk Corporation `1921` を 16 進表記した値である。VID は USB descriptor の申告値であり、chip identity や真正性の証明ではない。

実装は `crates/nclr-core/src/controller_protocol.rs` と `crates/nclr-backends/src/bin/nclr-controller.rs` にある。macOS では次の hardware-free 確認ができる。

```sh
cargo test --workspace
cargo run -p nclr-core --bin nclr-lab -- controller
cargo run -p nclr-core --bin nclr-lab -- decode "06 05 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
cargo run -p nclr-core --bin nclr-lab -- recipe --profile exact.toml --file recipe.json
```

正規 tool / service loader を再配布せずに取得・固定し、Mac 上の
Wireshark/TShark で USB BOT capture を厳密に変換する手順は
[`controller-artifact-workflow.md`](controller-artifact-workflow.md) にまとめた。

## 取得した vendor tool 実体

次の取得物を隔離した一時 directory へ保存し、Windows binary は実行せずに archive、PE metadata、import、文字列、同梱文書、loader / firmware header を静的解析した。repository へは格納していない。

| family | 取得物 | archive size | archive SHA-256 | 取得元の性質 |
|---|---|---:|---|---|
| Phison | [MPALL v3.63](https://flashboot.ru/files/file/398/) | 2,289,965 | `6ca4f67f50b930aecb5b9d450c38498bdbb76162d8e026be73f44bf775038a37` | vendor MP package の二次 archive。署名なし |
| Phison | [MPALL v3.72.0B](https://flashboot.ru/files/file/443/) | 2,156,227 | `756da586f67b3e06a09e97ee940994547b72fea7f64308a5c559e0b1689b5364` | vendor MP package の二次 archive。署名なし |
| Phison | [MPALL v5.13.0C](https://flashboot.ru/files/file/690/) | 4,275,144 | `e8ff9199b07a5e6878ce77180ea0f0594a9681c86c888e4e9f4550404bdbe1ab` | vendor MP package の二次 RAR。署名なし |
| Silicon Motion | [SM3257ENAA MPTool V2.03.58 v8 K1129](https://flashboot.ru/files/file/252/) | 2,749,932 | `5104694914741810a6dc6b9c2ac541d936737d4c94d1ae61bb7f09f2eb6f870f` | vendor MP package の二次 archive。PE は Silicon Motion metadata を保持するが署名なし |
| Silicon Motion | [Dyna SM3281 series U0204](https://flashboot.ru/files/file/689/) | 9,903,461 | `ff2143c5bf17ee91b5536c8d32953e73de0c36b92ff3455ddf5f46b02ea75153` | vendor MP package の二次 RAR。署名なし |
| Alcor | [ALCOR MP v13.10.28.01.C](https://flashboot.ru/files/file/408/) | 6,637,920 | `9b39018528d03465ad9a404d863a5b15cbf3955cd11ed30302c8d0fa0fdfc05a` | 掲載者が Alcor site 取得物と説明する二次 archive。署名なし |
| Alcor | [ALCOR U2 MP v20.09.16.00](https://flashboot.ru/files/file/683/) | 7,096,430 | `9a2e57e380d5cbee33d6c3b00a521337d97c0f11ff712f2d516bce1540aa10ea` | vendor MP package の二次 7z。署名なし |

SanDisk U3 tool だけは後述する SanDisk 正規 URL の保存 response と Authenticode を確認できた。Phison、SMI、Alcor は内部 version、vendor 文書、controller 固有 loader、NAND table が相互整合する実 MP package だが、現在の配布元は vendor 自身ではなく PE signature もない。このため「vendor 製 tool の内容を解析した」という技術的根拠には使うが、archive byte 列の供給 chain を正規署名済みと表現しない。

## Phison PS2251 family

一次資料:

- [Psychson](https://github.com/brandonlw/Psychson) は PS2251-03 の version page、NAND ID、BootROM 遷移、burner 転送を実装している。README は firmware `1.03.53` と 8K eD3 NAND 以外を未検証とし、正しい NAND 固有 burner が必要で、恒久破損の可能性があると明記している。
- [Psychson PhisonDevice.cs](https://github.com/brandonlw/Psychson/blob/master/DriveCom/DriveCom/PhisonDevice.cs) は `06 05` version page、`06 56` NAND ID、`06 BF` BootROM、`06 B1/B0` 転送、`06 B3` PRAM 実行の CDB を示す。
- [flowswitch/phison](https://github.com/flowswitch/phison) は PS2303 を BootROM 化し、揮発 PRAM コードを実行する public-domain 実装である。[Phison.py](https://github.com/flowswitch/phison/blob/master/host/Phison.py) は同じ version signature と転送シーケンスを独立に実装している。
- [nand_test.py](https://github.com/flowswitch/phison/blob/master/host/nand_test.py) は XDATA register access と NAND READ ID の研究コードだが、全 NAND geometry、ECC、FBB 保護、RBB、BBT/FTL commit を実装していない。

したがって BootROM / PRAM へ入れる事実だけで D1–D4 を宣言してはならない。nclr は `BtPramCd` の exact length、header/body 512-byte chunk、各 acknowledgement、run command、entry / loader の 2 段階 USB 再列挙を実装した。残る tuple 固有情報は、burner が公開する raw page/erase/status/metadata command と response layout であり、これを authenticated recipe に固定して NAND geometry / ECC layout ごとに HIL 認定する。

### MPALL 実ファイル解析

v3.63 と v3.72.0B は `MPALL`、`MPParamEdit`、`GetInfo`、`IDBLK_TIMING.dll`、controller `PS2251-67` 用 burner、複数 firmware を分離している。主要値は次のとおりである。

- v3.72.0B の `MPALL_F1_9000_v372_0B.exe` は 2,583,040 byte、SHA-256 `96614750c61e0ad6b05d19e74848c1679f6318dd21de6faee46c92fb05152142` で、`SetupAPI`、`CreateFile`、`DeviceIoControl` を import する。PE security directory は空である。
- `IDBLK_TIMING.dll` v1.2.74.0 は SHA-256 `99c5053f3db67cdb487666cba21fd485f716b3a12d3b4cc3d14e05e041f27fff` で、`DllGetFlashData`、`DllGetIDBlock`、`DllGetTiming`、`DllWriteBlock`、`DoPreformat` を export する。内部 NAND table は Flash ID、plane、I/O bus、page size、ECC、spare length、maximum block、read/write timing を別々に保持する。
- `BN67V1292KM.BIN` は 33,792 byte、SHA-256 `ccb05c6038e3ecb70fcdf102b5a4a229770d31106ce5d8e18085e5c86055238a`、`BN67V132M.BIN` は同じ size、SHA-256 `6c57fa6deeb5da5b980cd80690c2e071caa0e80efda1d762f394ef6f6de85f26` である。両方とも `BtPramCd`、little-endian page count `32`、512-byte header + 32 KiB body という nclr の parser 契約と一致した。
- v3.63 の `BN67V101M.BIN` は 32,768 byte、SHA-256 `6a1795097d08c9bfa07f4f2cf1164edc8ee95c3b1842987d2dc3890725133331`、page count `31` で、同じ parser 契約に一致した。
- firmware の `FW67FF01V60424M.BIN` と `FW67FF01V61110M.BIN` も `BtPramCd` marker を持つが、burner の page-count field ではなく別の multi-field header を使う。nclr はこれらを `phison-bt-pram` service-loader と誤分類しない。

main tool の文字列は `Wafer Erase All`、`Burner Erase All`、late bad block、CE / die / zone / block ごとの error、NAND test、ISP loader を区別する。したがって MPALL の物理処理は「共通 CDB だけ」ではなく、BootROM transport + controller/NAND 固有 burner + ID block/timing table の組である。nclr の `nclr-lab decode` は実装済み `06 B1` header/body transfer と `06 B0` acknowledgement の address / length も表示するようにした。

MPALL v5.13.0C はこの構造が後期 PS2251 にも継続していることを確認するために追加取得した。`MPALL_F1_9000_v513_0C.exe` は version 2.0.1.6、8,819,712 byte、SHA-256 `f61e264404e768e80f1fe09c09205882b42eb2c2c773b18926e86070b28f0704` の 32-bit PE で、security directory は空である。package の対象と loader は次のように分離される。

- PS2251-61: `2261PRAM_20171019.BIN`、98,816 byte、SHA-256 `6046750a5ef7e65253d18328e61f02c90dba47f896951175255bc467812ce02f`。
- PS2251-07: `2307PRAM_FF01.BIN`、115,200 byte、SHA-256 `50b3e258d4d7d7ab83cd30f184d76b984bf67099091128956c9dd8afea8cd73e`。
- PS2251-09: `2309PRAM_7.00.5D.T_20171130.BIN`、254,464 byte、SHA-256 `0999b56de61e07a2817954776fc2b6a35020beec7e730ec529245f341d32bd6a`。Micron FSP 版は同 size、SHA-256 `5e73e86e056255b5add6b0b7b390e39c727647553dc95d9b9a54b4014e9ee6fd`。

これらは全て 512-byte `BtPramCd` header を持つが、旧 31／32 KiB burner の page count ではなく、先頭 3–4 byte の segment descriptor を使う。body はそれぞれ 96／112／248 KiB である。nclr は旧 `phison-bt-pram` と後期 `phison-bt-pram-extended` を分離し、後期形式では 1 MiB 上限、512-byte alignment、reserved header、uniform body を検査してから、32 KiB 上限の複数 `06 B1 02` transfer を構成する。通常 firmware も `BtPramCd` marker を持つため、format 検査だけで loader と認定せず exact digest と controller tuple を必須にした。後期 controller でこの transport を production 認定するには、同一 tool / device tuple の USB trace で command と acknowledgement を一致させる必要がある。

v5.13 は PS2251-67／-68／-69／-70／-07／-09 の NAND 別 firmware、`b2267_bank.bin`／`b2269_bank.bin`／`b2307_bank.bin`／`b2309_bank.bin`、更新版 `IDBLK_TIMING.dll` v1.4.44.0 を別 object として持つ。main tool 内には PS2251-01／-02／-03／-06／-07／-08／-12／-13／-30／-33／-37／-38／-39／-50／-60／-61／-62／-63／-67／-68／-80／-85 の分岐文字列がある。ただし package に分岐が存在することは、その全 controller で共通 BootROM command と response が同一である証拠ではない。実 profile は controller chip type ごとに分ける。

## Alcor AU698x

一次資料:

- [alcorhack](https://github.com/tizbac/alcorhack) は作者の AU698x リバースエンジニアリング実装である。
- [作者の調査記録](https://linuxehacking.ovh/2014/07/20/alcor-ufd-controller-hacking-update-2/) は `82 51 01` による 512-byte config read と `81 00 ff` による config upload を説明するが、実験段階である。
- [main.cpp](https://github.com/tizbac/alcorhack/blob/master/main.cpp) は `FA 00` flash-ID read と物理 sector read の研究経路も含む。ただし、準備 blob の意味、geometry、ECC、消去、BBT/FTL commit は確定していない。

`0x81` はソース中で rebuild と呼ばれる箇所があるが、確認できる効果は USB 設定の upload / regenerate であり、D1–D4 の完全消去を意味しない。nclr はこの write CDB を hard-code しない。正規 tool trace で物理 erase、raw page、status、BBT/FTL commit の個別 semantics が確定した exact tuple だけを Alcor recipe として実行できる。

### AlcorMP 実ファイル解析

archive 内の `AU698X MP user's manual_Chinese.pdf` は Alcor Micro International / 群勝科技名義、作成日 2013-04-25、SHA-256 `b9a3890313b8e16e90ebe95ca21bdda6bd826b147f613edd5d72c2a0dad754a7` である。本文は最大 16 台、Flash ID / CE / channel 自動識別、raw bad-block marker 読み出し、全 block への write/read compare、全情報消去、旧 MP bad-block 情報の再利用、予約 block、ECC 0–15、full / quick scan を明記する。これは D1–D4 相当機能が実 tool に存在する直接の vendor 文書である。

`AlcorMP.exe` は 2013 年 10 月 build、SHA-256 `32d90a6b07282cf2010635897a3680f8cf79171bb66bb21313aa5994c46aaee2`、`UfdApi_Gen.dll` は SHA-256 `a295ca70372edbbc59f3d33a7ff91e32a177b0240889d5633f9f67397421a6b1`、`UfdComLib.dll` は SHA-256 `0c1c1b2020892675add4b55b94399cf487290cb2b4b8c3d4e7cbccf4005043b3` で、いずれも署名されていない。構成は次のように分離されている。

- `UfdCom/CTL/10/10_GEN.BIN`: controller generation code。ASCII hex 化された 8051 code。
- `UfdApi_Gen/CTL/10/BIN/*.BIN`: NAND family 別 low-level code。
- `SCAN_BIN/*_SCAN.BIN` / `*_SORT.BIN`: raw scan / bad-block sort code。
- `FlashList.ini` / `FlashList.dat` / encrypted `flashlist.afl`: 6-byte Flash ID、driving level、NAND 固有設定。
- `LLF.dll`: 1.5 MiB の opaque LLF payload。通常 PE DLL ではない。

`UfdApi_Gen.dll` は page mapping、original / current bad block、physical page、reserve block、scan pattern、EraseAfterMP、BBT read/write failure を個別に扱う。したがって `82 51 01`、`FA 00`、`81 00 FF` の 3 command だけを hard-code しても正規処理にはならない。controller code と NAND scan code の upload sequence、response signature、BBT / reserve metadata commit を capture から recipe 化する必要がある。

ALCOR U2 MP v20.09.16.00 も追加取得し、2013 年版の分離構造が 3D NAND 世代でも維持されることを確認した。`AlcorMP.exe` は version 3.1.1.33、548,864 byte、SHA-256 `7e4eda0629333e7921c5f73a8300de6d959cf25eb34c0fa626eaa16357770362`、`UfdApi_X3.dll` は 1,736,704 byte、SHA-256 `52c06d1ce3537e431f72d226bfc05a8dc0b6180d72030d0fc47be9c2d32a8340`、`UfdComLib.dll` は SHA-256 `0f215cc08232232d7dbddee85d6a9e8adbff68d337f6add140ea44f1d6e85f01` で、全て署名なしである。2019 年版 vendor manual は SHA-256 `1bce74e048acdf8d6878d7613e59ccc97a3b5be0c7e5e0059e3d5631f7ceb1d7`、2020 年 change log は SHA-256 `14454f9cfa0db097a92407e6c65236ede5c08e14629538eaa4f7f8c8f018b3e7` である。

後期 package は `CTL/28` の controller code、NAND 別 `BIN`、diagnostic `DGD_BIN`、physical scan / low-level format 用 `SCAN_BIN`、`SORT_BIN`、short / long bootloader、opaque `LLF.dll` を分離する。change log は AU6989SN-TA／GTC／GTD／GTE、Toshiba／SanDisk Gen4.5、Micron／Intel B16A／B17A／B27A／N18A／N28A、Samsung、Hynix、YMTC を個別に扱い、古い controller や古い MP との high-level format 互換性がない組み合わせも明記する。従って Alcor も `AU698x` という 1 recipe ではなく、controller generation + full NAND ID + selected BIN / SCAN loader の exact tuple が必要である。

## Silicon Motion

製品一次資料で確認できるのは controller 能力までである。これとは別に、公開された Linux `sg_raw` transcript から読み取り専用 identity page の 1 command だけを clean-room 実装した。

- Silicon Motion の [SM3267 発表](https://ir.siliconmotion.com/news-releases/news-release-details/silicon-motion-introduces-sm3267-ultra-high-performance-cost) は NAND 種別、性能、量産向け turnkey solution を説明するが、service CDB は公開しない。
- [SM3282 product brief](https://www.siliconmotion.com/download/p/a/SM3282_PB_EN_201910.pdf) は UASP、NAND channel、ECC、turnkey firmware を説明するが、物理消去・BBT/FTL 再構築のホストプロトコルは公開しない。
- [公開調査記録](https://sstahlman.blogspot.com/2021/) は `sg_raw -r 1024 ... f0 04 00 00 00 00 00 00 00 00 00 02` と、offset `0x20` の `2013-02-26  SM3257ENLTBA   SMI32X` response を掲載している。nclr は transfer 1024 byte、printable ASCII、日付、`SM3...` part、`SMI32X` signature を全て検査し、identity にだけ利用する。
- SD controller については [SM2707EN product brief](https://www.siliconmotion.com/download/3PN/a/SM2707EN_PB_EN.pdf) が標準 SD full-user-area logical erase を記載する。しかし、これは D0 の標準論理範囲であり、D1–D4 の vendor service protocol ではない。

`F0 04` 以外の bounded destructive command、response signature、失敗時復旧は公開資料から確定できない。特に `0x2a` parameter への言及だけから CDB layout を作らない。メーカー資料、再配布可能な SDK、または所有する犠牲媒体と正規 MPTool の USB trace から確定した command は、SMI recipe engine へそのまま投入できる。

### SM3257ENAA MPTool 実ファイル解析

`sm32Xtest_V58-8.exe` は version 2.3.58.8、build timestamp 2011-11-29、2,240,512 byte、SHA-256 `82ebcc3b9502452638f74a7449d6cb95bdd4abd90f3ce9284ebed7e0d4902845` である。PE version resource は `Silicon Motion Technology Corp.` と copyright 2011 を保持するが、security directory は空である。同梱 release note は `SMI CONFIDENTIAL`、作成日 2011-11-30、SHA-256 `010e8e66bc63d1fdcd695654943ba062c10f230723400690eefe9671a23b7dd9` で、SanDisk 24 nm MLC read-retry table、system block erase、original bad-block scan、full ISP write、ISP checksum を version ごとに説明する。

package は SM3254AE / SM3255AB / SM3255ENA1 / SM3257AA / SM3257ENAA / SM3260AB ごとの `.dbf` と ForceFW mapping、NAND vendor / generation ごとの ISP / pretest、CardMode boot image を分離している。

- `flash_3257ENAA.dbf` は 24,813 byte、SHA-256 `4b317d1fca8cab579f9b9a84c15aa53642943c364dd46d22d3a50fa9e93a8d29` で、6-byte Flash ID と geometry / timing / ECC parameter を持つ text table である。
- `SM3257ENAA.FFW` は 11,621 byte、SHA-256 `1e99ce14d18e6832f19b75bdc03165fbdf562dcbe49962e3611d6ab3b3b4b6ba` で、完全な Flash ID ごとに ISP と PTEST を選ぶ。
- default `SM3257ENAAISP.BIN` は 71,680 byte、SHA-256 `49da877e11c49624773894ac1e7e872eda88a6816a2b644c7f4c153fbb26d1a6`、header 内に `SM3257ENAA` と firmware `111123-AA-` を持つ。
- `SM3257ENAAPTEST.bin` は 24,576 byte、SHA-256 `cd39a2f34100df1742bb65773a1b3a893f85d40c1408da483eace30731237486` で、original bad block を検出する pretest code である。

main tool は Info Block と backup、ISP block、spare、erase count、original/new bad block、CE / plane / block / page、ECC、read-retry を区別する。これも host の単一 erase CDB ではなく、Flash ID で選んだ NAND-specific ISP / pretest を controller へ導入して処理する構造である。nclr の `F0 04 00 00 00 00 00 00 00 00 00 02` はこの package と同じ SM32X family を識別するが、NAND ID ではないため、`nclr-lab decode` でもその境界を明示する。

Dyna SM3281 series U0204 も追加取得した。`SMIMPTool.exe` は version 21.2.1.1、3,588,096 byte、SHA-256 `e5d95716610c173a5f11b655e53ef39a5dde5f8f81ee9df5b94cdf65c7c1a5f7`、署名なしである。一方、`PretestGP3265_U0203V1.dll` は Silicon Motion Inc. metadata を持つ version 21.2.3.1、SHA-256 `464381a2b9164834e6547c9cb9bf0b066bb9b5c8ec684d50ddcdab27de97f63e`、`PretestGP3271_U0115V2.dll` は version 21.1.15.2、SHA-256 `43870049820bad7a024e182bce59520fc400338d86c40ffc83b93a0639e53dc3` である。

package は SM3265AB、SM3271AB／AD／BA、SM3281AB／BA／BB ごとの `.FFW`、SM3265AB／SM3271AB／SM3281AB／BB ごとの `.dbf`、1,886 個の NAND / ISP / pretest `.bin`、211 個の `.ebi`、controller 別 read-retry table を分離する。例として `SM3265AB.FFW` は SHA-256 `a6d7cbde3eab116491f0116d69b91ece6bf1999809b730d595556af60f4bfca4`、`SM3271BA.FFW` は `3e68061e965d9a08c1f08c80354bbdb126d93e5bc461d5be814261765e2a65b5`、`SM3281AB.FFW` は `282d96c219f280a798f33a7fb13cc38eee3f71ba1fc43af43b363b0a9419c1da` である。pretest module の文字列は system page/block、original page count、ISP block count、backup page、remapping、SLC/TLC spare pool、ECC 144、read-retry table、multi-CE / plane を個別 field として扱う。

旧 `UFDIF.dll` には SM325x／SM326x の分岐が残る一方、後期 controller は別 pretest DLL と ISP 群へ委譲される。公開 `F0 04 ... 02` identity command の 12 byte 固定列は後期 PE 内に静的定数として存在せず、動的構築の可能性もあるため、これだけを根拠に SM3281 へ対応済みとはしない。SM3281 系では exact USB / SCSI bootstrap で recipe artifact だけを選び、USB trace 由来の `read-controller-id` / `read-nand-id` response を破壊境界より前に完全一致させる経路を実装した。旧 SM3257 の response parser へ暗黙 fallback しない。

SMI の公開 identity page は NAND ID を返さないため、plan 時は exact controller / firmware に一致する production profile が trusted directory 内で 1 個だけの場合に限って候補を選ぶ。run の破壊境界より前に、その profile が digest 固定した recipe の `read-nand-id` を実行し、payload byte 列が recipe / profile の exact NAND ID と一致しなければ拒否する。同じ controller / firmware に複数 NAND profile がある曖昧な構成は plan 時点で hard error となる。service firmware への再列挙後は、通常 firmware の identity を推測せず、継承済み artifact role と fsync 済み controller state の profile / recipe / plan binding でのみ処理を継続する。

## SanDisk Cruzer / `82-00263-1`

実基板情報から確認できる範囲は次のとおりである。

- [Donor Drives の Cruzer 4 GB 基板情報](https://www.donordrives.com/sandisk-cruzer-4gb-sdcz36-004g-82-00263-1-sdtnnnahem-004g-usb-2-0-flash-drive-25404.html) は SDCZ36-004G、controller marking `82-00263-1`、NAND `SDTNNNAHSM-004G` の組み合わせを示す。
- [Flash Extractor の Cruzer Slice 4 GB 解析](https://flash-extractor.com/forum/viewtopic.php?t=5829) は同じ controller marking と `SDTNNNAHEM-004G`、16-bit ID `45 c7 98 b2`、別 XOR 条件を報告している。
- [別の Flash Extractor 解析](https://flash-extractor.com/forum/viewtopic.php?p=35665) も `82-00263-1`、ID `45 c7 98 b2`、16-bit bus、1 x 4 GB、page `8640`、block `0x195000` を報告する一方、既知 XOR profile と sector size が合わないとしている。
- [8 GB 個体の解析](https://flash-extractor.com/forum/viewtopic.php?t=5677) は同じ `82-00263-1` と `SDTNNNBHSM-008G`、ID `45 ce 99 b2` を報告し、物理 NAND は 8-bit chip を 16-bit bus に配線した `16-8` mode だったとしている。[別の 8 GB Cruzer Blade donor](https://www.donordrives.com/sandisk-cruzer-4gb-sdcz36-004g-82-00263-1-sdtnnnahem-004g-usb-2-0-flash-drive-25406.html) では `SDTNNNBHEM-008G` との組み合わせも確認できる。
- 公開されている [CBM209X flash support list](https://f-hauri.ch/vrac/SSD-16Tb/CB/219x/CBM219X%20UMPToolV7200%282022-04-28%29/CBM209X%20Flash%20Support%20List%282020-8-21%29.pdf) には `SDTNNNAHSM-004G(D3)`、ID `45C798B276D5`、TLC 8K、72 bit / 1K ECC、32 nm の記載がある。ただし別 controller tool の表なので、Cruzer の geometry を確定する一次証拠には使わない。
- open-source の [u3-tool](https://git.in-ulm.de/cbiedl/u3-tool) は Cruzer Micro U3 を SCSI pass-through で扱うが、公開機能は CD partition、data partition security、unlock である。raw NAND、retired block、BBT / FTL metadata の処理ではないため、D1–D4 command の根拠には使わない。

### SanDisk 正規 U3 tool の実ファイル解析

SanDisk が案内していた `LPInstaller.exe` と `launchpadremoval.exe` を、実行せず Mac 上で静的解析した。取得 byte 列は第三者配布物ではなく、Wayback Machine が SanDisk の正規 URL から保存した response である。

| tool | 正規 URL の保存日時 | version | size | SHA-256 | 署名 |
|---|---|---:|---:|---|---|
| LPInstaller | [2006-07-08](https://web.archive.org/web/20060708003617id_/http://u3.sandisk.com:80/download/apps/LPInstaller.exe) | 1.0.0.12 | 1,140,360 | `f6d34f00449816523d75092c0385cd7e0aa3f4591b73ee77a47c441eda33f8c4` | SanDisk Corporation Authenticode |
| LPInstaller | [2007-02-22](https://web.archive.org/web/20070222125648id_/http://u3.sandisk.com:80/download/apps/LPInstaller.exe) | 1.0.0.18 | 1,255,048 | `8121d033dfeb32ee84d6630c05fb09208ff34fe57cee1bd654efd66d5d095e18` | SanDisk Corporation Authenticode |
| LPInstaller | [2011-06-16](https://web.archive.org/web/20110616074940id_/http://u3.sandisk.com/download/apps/LPInstaller.exe) | 1.0.2.36 | 1,039,736 | `976a843ee5a35e5015b5b2394e520e82403e6f81f877a4206bfe705bcb5e13e4` | U3 LLC Authenticode、署名時刻 2008-08-31 13:21:50 UTC |
| Launchpad Removal | [2006-07-17](https://web.archive.org/web/20060717010700id_/http://www.sandisk.com:80/Assets/u3/launchpadremoval.exe) | 1.0.0.21 | 2,461,696 | `3b272167a5a0d64dcb196bce224eb0bd250270a90a6be5fa166ed3816a4a6584` | PE signature なし |
| Launchpad Removal | [2012-05-28](https://web.archive.org/web/20120528064506id_/http://www.sandisk.com/Assets/u3/launchpadremoval.exe) | 1.0.2.32 | 3,493,888 | `b2d1a3483cb19b44b7e95b9c69f98215da8f161e729a63069d40fe5ef2ab1404` | PE signature なし |

1.0.2.36 の PE Authenticode は古い MD5 署名なので現在の暗号強度はないが、PE checksum field と certificate table を除外して再計算した Authenticode digest `20e63b5c6974fd6d31a771e859816e2c` は SignedData 内の値と完全一致した。さらに、別の Internet Archive item から取得した同名 file と SanDisk 正規 URL の 2011 年 response は 1,039,736 byte 全体が一致した。

3 世代の LPInstaller と 2 世代の Removal Tool はいずれも `MUSK SDK`、`U3CfgCommands.cpp`、`U3CDCommands.cpp`、`SCSICommands.cpp` を含む。後期 Removal Tool の本処理は `CConfigServiceImpl::setDomains` であり、Vista では `DISABLE_FORMAT` flag を付ける分岐がある。LPInstaller は user data の backup、U3 domain の再構成、`cruzer-autorun.iso` 相当の CD image 書き込み、logical volume format、restore を行う。

正規 binary の constructor と [u3-tool 0.3 source](https://sources.debian.org/src/u3-tool/) を相互照合すると、関連する 12-byte CDB は次の範囲である。

| CDB | 意味 | D1–D4 への適用 |
|---|---|---|
| `FF 00 00 ...` | U3 property read | controller / logical property。NAND ID ではない |
| `FF 03 01 ...` | USB controller chip manufacturer / revision | controller identity。NAND ID ではない |
| `FF 20 00 ...` / `FF 21 00 ...` | domain size rounding / domain info | logical partition metadata |
| `FF 22 00 ...` | `setDomains` | U3 logical partition 再構成。physical block erase ではない |
| `FF 23 00 ...`–`FF 25 00 ...` | U3 configuration private command | raw NAND semantics を示す証拠なし |
| `FF 40 00 ...`–`FF 42 00 ...` | U3 CD domain operation | logical CD image。raw page/OOB ではない |
| `FF A0 00 ...`、`FF A2 00 ...`–`FF A7 00 ...` | data partition info / security | logical/security metadata |
| `FF 01 01 ...` | reset / reconnect | controller reset。erase ではない |

CD write の CDB layout は `FF 42 00 <domain:u8> <block:be32> <count:be32>` で、data-out は `count * 2048` byte である。これは ISO block write であり、NAND page、OOB、CE / LUN / plane / block address を持たない。

[SanDisk の現行 U3 終了告知](https://support-en.sandisk.com/app/answers/detailweb/a_id/37774/~/u3-launchpad-end-of-support) は 2009 年末から U3 を段階的に終了し download server も停止したと説明する。[現行の削除手順](https://support-jp.sandisk.com/app/answers/detailweb/a_id/36817) も対象を U3 機能搭載 Cruzer に限定する。したがって、この正規 tool 群は U3 ではない Cruzer Blade / Slice の `82-00263-1` を識別・初期化する tool ではなく、D1–D4 の根拠にできない。

nclr はこの境界を code でも固定した。`nclr-lab decode` は既知 U3 CDB を logical domain / CD / security command として表示し、`sandisk-cruzer` recipe validator はこれらを `read-bbt`、`read-page`、`erase-block`、`program-page`、BBT / FTL prepare / activate などの raw NAND role に割り当てた recipe を拒否する。例外は `FF 00 00` / `FF 03 01` の `read-controller-id` と、`FF 01 01` の `reset-controller` だけである。

これらは controller / NAND inventory の根拠であって、SanDisk の raw NAND service CDB、BBT、FTL metadata format を定義しない。また `82-00263-1` は PCB 上の marking であり、USB response がその文字列をそのまま返す保証はない。そこで nclr は次の境界を実装した。

1. USB VID `0781` では未知の vendor CDB を送信せず、profile の exact USB / SCSI bootstrap に一致する runtime artifact 一覧だけを plan へ固定する。
2. 正規 tool capture から得た stable controller-owned payload を recipe の `controller_identity_hex` と必須 `read-controller-id` command に固定する。
3. run の破壊境界より前に controller identity payload と完全な NAND ID payload の両方を byte 単位で照合する。
4. 同一 bootstrap tuple に複数 profile が一致する場合、短い NAND prefix しか得られない場合、または response が全 `00` / 全 `FF` の場合は拒否する。
5. `SDTNNNAHSM` / `SDTNNNAHEM` / `SDTNNNBHSM` / `SDTNNNBHEM`、8-bit / 16-bit / 16-8 表現、XOR / randomizer、page/OOB、ECC layout を別 tuple とし、`82-00263-1` だけを根拠に geometry を共用しない。

このため engine は `82-00263-1` を含む SanDisk proprietary controller recipe を実行できるが、repository には未確認 PID、firmware、CDB、geometry を埋めた production profile を同梱しない。対象個体の正規 tool capture から exact `read-controller-id`、`read-nand-id`、physical erase / raw page / status / BBT / FTL commit command を抽出し、同一 tuple の recipe として固定する必要がある。

## USBest UT163

一次資料:

- [USBest UT163 datasheet](https://opendevices.ru/wp-content/uploads/2011/11/USBest_UT163.pdf) は USB 2.0 flash disk controller の機能を説明するが、SCSI ベンダー固有コマンドや service mode の protocol は公開しない。
- [UT163/UT165 USB Flash Disk Utility の user manual](https://archive.org/details/manualzilla-id-5806917) はパーティション、boot disk、secret area の使い方を説明する Windows ツールの説明であり、ホスト protocol 定義ではない。
- usb.ids は `4146` を "USBest Technology" に、`1307` を "Transcend Information, Inc." に登録するが、USB-IF の registry 議論は `1307` を USBest Technology Inc. の割り当てとする。いずれも識別のヒントに過ぎない。

実測 (Imation Flash Drive Mini、VID `0718`、UT163 搭載): 標準 INQUIRY を 96 バイト要求すると、36 バイトの標準データを超える vendor-specific 領域に `UtffU163A1BM` のマーカーが返る。`profiles/identify-usbest-ut163.toml` が VID ヒント (`4146`、`1307`) と INQUIRY マーカー (`U163`) を宣言し、nclr はこの領域のパターンを検証して `usbest-ut163` と識別する。この識別は標準 INQUIRY だけを使い、未知の vendor CDB を送信しない。識別は読み取り専用の情報提供であり、destructive capability は公開 service CDB が存在しないため一切公開しない。

## C3 / C4 へ昇格する認定条件

ファミリー名単位ではなく、次の組み合わせごとに fixture を固定する。

1. controller chip type / revision
2. firmware version と service-mode firmware / burner の SHA-256
3. NAND maker ID、device ID、dies、CE、planes、pages/block、page/OOB size
4. randomizer、read-retry、ECC strength と parity layout
5. FBB marker location と保護規則
6. system block、old/new BBT、FTL journal / generation の layout
7. 正常、weak block、old RBB、erase failure、program failure、電源断の各 fixture
8. 独立 reader で D0–D4 へ既知 pattern を事前配置し、処理後に全対象を再読する証跡

1 組でも不明なら、その領域は `unreachable` または `unknown` のままにする。成功 status だけを根拠に trust を `production` へ変更しない。

プロファイル検証もこの境界を強制する。実媒体で `trust = "production"` を指定する場合、firmware / NAND 範囲は `min = max` の完全一致、D1–D4 の全 accounting、BBT / FTL / spare rebuild、独立 HIL report の SHA-256、reader 名、sample 数、power-cut case 数が必須である。さらに clean-room / runtime artifact の provenance、protocol trace、exact NAND geometry、FBB marker、randomizer / read-retry / ECC layout、BBT / FTL / spare format、atomic commit protocol、明示 policy 付き system block range、exact runtime recipe を必須とする。recipe schema と crash/re-enumeration 契約は [`controller-protocol-recipe.md`](controller-protocol-recipe.md) に記載する。`simulated = true` は組み込み `sim-controller-1` 以外では拒否される。
