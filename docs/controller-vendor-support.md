# ベンダーコントローラー対応調査

この文書は、実 USB フラッシュ媒体について D1–D4 へ到達するための公開一次資料、実装済み範囲、認定されていない範囲を分離して記録する。

## 結論

2026-08-13 時点の実装と、repository に同梱していない実測 tuple を分ける。ここで「recipe 対応」は bounded command grammar と artifact 検証へ接続済みという意味であり、controller line 全体の service command が判明したという意味ではない。

| canonical family | 調査対象 controller line | 組み込み固定 probe の範囲 | recipe adapter | production tuple |
|---|---|---|---:|---:|
| `phison-ufd` | PS2251-01〜85、PS2318/2319、U17/U18 | PS2251 version-page-compatible response + NAND ID | あり | 0 |
| `alcor-ufd` | AU698x、AU6989SN、AU6990/AU6998 | AU698x `99 07` config-compatible response + flash ID | あり | 0 |
| `silicon-motion-ufd` | SM32X、SM3255/57、SM3265/67、SM3271/81、SM2320/21/22 | SM32X `F0 04` identity-page-compatible response | あり | 0 |
| `sandisk-cruzer` | Cruzer proprietary、`82-00263-1` | なし | あり | 0 |
| `usbest-ufd` | UT163、UT165/166/167、UT190/192 | UT163-compatible standard INQUIRY marker | あり | 0 |
| `chipsbank-ufd` | CBM2098/99、CBM2198/99 family | なし | あり | 0 |
| `innostor-ufd` | IS916/917/917CP、IS918/918M、IS818 | なし | あり | 0 |
| `firstchip-ufd` | FC1178/79、FC2279、FC3379、ZC3281、YB/YC2019 | なし | あり | 0 |
| `solid-state-system-ufd` | SSS6677/79、6688/89、6690/91/92 | なし | あり | 0 |
| `skymedi-ufd` | SK6211、SK62xx、SK66xx | なし | あり | 0 |
| `appotech-ufd` | DM8216/31/35、DM8261/A、YS8231 | なし | あり | 0 |
| `silicongo-ufd` | SG1580/81、KS6808、UD6809 | なし | あり | 0 |
| `icreate-ufd` | i5060/62、i5122/27/28/29、i5188 | なし | あり | 0 |
| `oti-ufd` | OTi2165〜2169、2189、6128、6228、6828 | なし | あり | 0 |
| `prolific-ufd` | PL-2515/PRO、PL-2518、PL-2528 | なし | あり | 0 |
| `ameco-ufd` | MXT6208、MXT8208、MW8209/8289/8690 | なし | あり | 0 |
| `netac-ufd` | NT2033/39、NT2060 | なし | あり | 0 |
| `efortune-ufd` | eU201 variants、eU202 | なし | あり | 0 |
| `ite-ufd` | IT1165/67、IT1171/72/76/77、IT1181/99 | なし | あり | 0 |
| `hyperstone-ufd` | U8/U8B、U9 | なし | あり | 0 |
| `yeestor-ufd` | YS USB 2.0、YS5083/85、YS5283HP | なし | あり | 0 |
| `ramos-ufd` | UR22/24/25/26、UR28/30/31 | なし | あり | 0 |
| `trek2000-ufd` | TD2SMG9/TD2SM9、legacy ThumbDrive | なし | あり | 0 |
| `moai-ufd` | MA8100/02/03、MA8125 | なし | あり | 0 |
| `realway-ufd` | RW8021、CION AR192/AP192 | なし | あり | 0 |
| `huayi-ufd` | HY6919 | なし | あり | 0 |
| `ktc-ufd` | FC1325N | なし | あり | 0 |
| `smsc-ufd` | USB97C242 | なし | あり | 0 |

全 28 family は controller/NAND identity、page + OOB read、physical erase/status、BBT、FTL、capacity metadata、service transition、resume/salvage の同じ検証済み役割へ接続される。さらに全 28 family は、exact USB descriptor + SCSI bootstrap で 1 個の `probe-*.toml` を選び、trace 由来の固定 `read-controller-id` と `read-nand-id` を実行する共通 read-only probe 基盤を利用できる。固定 probe のない 24 family と、固定 probe の対象外世代では、この package probe または full recipe の 2 段 identity が必要である。したがって上表の adapter 数や package probe 対応を C3/C4 対応媒体数として数えてはならない。

「MPTool で初期化できる」「コマンドが GOOD status を返す」「ファームウェアを書き換えられる」は、D1–D4 の処理証拠ではない。C3 を有効にするには、少なくとも全非 FBB ブロックの列挙、D1/D2 の物理消去、旧 RBB の個別消去結果、旧・新 BBT 差分、旧 FTL 世代の無効化、新 FTL の commit、電源再投入後の独立確認が必要である。

## 実装した安全境界

- USB VID は送信してよい読み取り専用プローブを 1 ファミリーへ限定するヒントとしてだけ使う。OEM VID を推測して総当たりしない。OEM VID は trusted production profile の exact USB / SCSI bootstrap が明示した family と runtime identity recipe でのみ扱う。
- VID からベンダー名・モデル名を表示するときは、ツール固有の表を持たず OS の usb.ids (linux-usb.org、udev hwdb の生成元) を読み、無い場合はデバイスの iManufacturer 文字列にフォールバックする。ベンダー名はブランド情報であり、コントローラ family の断定には使わない (例: Imation ブランドの UT163)。
- 読み取り専用の controller family 識別パラメータ (VID ヒント、INQUIRY マーカー、報告名) は `profiles/identify-*.toml` に置き、コードへ埋め込まない。現在 18 profile を source package と installer の両方へ含める。ファミリ名は単一 registry と照合して検証する。vendor-owned VID を安全に特定できない 10 family は、誤推定を避けるため VID profile を同梱しない。
- Phison は vendor version page の `VR` シグネチャ、big-endian chip type、firmware bytes、run mode を検証する。続いて 6-byte NAND ID を取得し、全 `00` / 全 `FF` を拒否する。
- Alcor は 512-byte config の `99 07` シグネチャ、little-endian VID/PID/bcdDevice、USB string descriptor の型・偶数長・境界を検証する。シグネチャ確認後だけ flash ID を取得する。
- SCSI INQUIRY の vendor/product/revision 文字列を単独の controller 推定には使わない。署名済み production profile が USB VID/PID/bcdDevice と SCSI 3 文字列を全て固定した exact bootstrap tuple に限り、runtime recipe の候補選択へ使用する。
- 安全に送れる固定 identity CDB が公開されていない family、後期 controller、OEM VID 製品では、exact USB VID / PID / bcdDevice / manufacturer / product / serial と SCSI INQUIRY tuple を recipe artifact 選択に限って使う。空文字も wildcard ではなく exact absence である。この bootstrap は capability を有効化せず、runtime recipe の signed `read-controller-id` と `read-nand-id` が一致した後だけ実行可能にする。
- production TOML だけでは実行 capability を公開しない。読み取り専用 plan probe は必要 runtime artifact を plan へ固定するだけである。run の再 probe で exact tuple に固定された runtime protocol recipe と必要な loader が認証され、controller response の exact identity が一致しなければならない。protocol trace と qualification report は profile の認定根拠として SHA-256 を固定する。
- コンパイル済み support は USB VID ではなく、署名検証済み controller response へ結び付ける。probe 失敗時や `unidentified` を名乗る profile は実行可能にならない。
- controller backend は core が同一 SCSI object から解決した `/dev/sgN` を必須とし、block fd と sysfs `device` が一致しなければ拒否する。
- 不明な vendor opcode、OEM VID に対するファミリー横断プローブ、Alcor `0x81` config write、Phison BootROM 遷移は通常の `probe` で送信しない。
- `nclr-lab probe new` は `nclr info -j` の exact tuple から全 family 用の不完全 skeleton を生成する。`probe check` は exactly 2 個の fixed device-to-host CDB、bounded timeout / transfer、response signature、controller payload、完全な NAND ID、trace digest、HTTPS source を要求する。profile に trust や write role はなく、成功しても destructive capability を公開しない。
- macOS の `nclr info` と `nclr-lab probe run` は package-managed exact profile が 1 個だけ一致する場合に Apple SCSITask で 2 個の read を実行できる。system disk、non-removable、mounted、holder 付き媒体を拒否し、Apple が許可する exact 6 / 10 / 12 / 16-byte CDB 以外を暗黙変換しない。
- `nclr-lab tool` は全 28 family の package inventory marker と共通 NAND / BBT / ECC / loader vocabulary、Phison / Alcor / SMI の公開固定列、SanDisk U3 の source literal と x86 constructor を静的抽出する。schema 2 は SMI FFW の controller + exact 6-byte NAND ID + artifact 代入、Alcor の exact FID と CTL generation module 表も抽出し、競合、参照欠落、basename ambiguity を明示する。これは追加対応の調査入口であり、出力は常に candidate-only / production-ineligible である。
- destructive recipe engine は CDB opcode を固定し、可変 field の byte 0 上書き、overlap、範囲外 transfer、署名のない status / commit response を拒否する。旧 RBB は消去後も再利用せず、FBB と preserve system range を target から除外する。
- BBT / FTL は inactive 固定長 image、exact checksum algorithm / coverage、prepare / commit marker、generation を recipe で明示し、activate 後に BBT state と commit generation を再読する。host response 消失時は commit state を先に照会する。
- service mode の USB reset は同一 physical USB path 上の唯一の whole device だけを再 bind し、2-slot SHA-256 controller state と fsync journal から再開する。

ヒントに使う値は [USB-IF Company Vendor ID List](https://www.usb.org/sites/default/files/vendor_ids07072026_0.pdf) と vendor 資料を照合する。例えば `13fe`、`058f`、`090c`、`0781` は Phison Electronics Corp. `5118`、Alcor Micro Corp. `1423`、Silicon Motion Taiwan `2316`、SanDisk Corporation `1921` を 16 進表記した値である。VID は USB descriptor の申告値であり、chip identity や真正性の証明ではない。

実装は `crates/nclr-core/src/controller_protocol.rs` と `crates/nclr-backends/src/bin/nclr-controller.rs` にある。macOS では `diskutil` と IOKit registry を対象 BSD disk の provider chain で結合し、未知 command を送らず exact USB descriptor、SCSI tuple、location ID を `nclr info -j /dev/diskN` に収集する。native SD は取得可能な CID/CSD/SCR と card / host identity を `sd_research` に保存し、標準 SD host interface が公開しない内部 controller identity と C3/C4 service 情報を不足項目として分離する。次の hardware-free 確認もできる。

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
| FirstChip | FirstChip MPTools 20200430 FC1178/FC1179 | 6,975,361 | `02dee6595b7632090f676606d65592f5ce004b9436bcd800bb31b30391b708ee` | [二次 archive catalog](https://flashboot.ru/files/)。external code、scan code、seed、NAND parser を分離 |
| ChipsBank | APTool V7200 CBM2099/2199 | 7,650,649 | `deefbb11950790099c30a37467a9466301e24a2bf34cf85dde2d9bc3418226b3` | [二次 archive catalog](https://flashboot.ru/files/)。controller/NAND code と `.cbm` payload を分離 |
| Innostor | IS917 MP Package 917106M75-6_ST | 2,703,195 | `1fb840c575870d639ee788cb4ef5e14d392be8df27bddf8d9f920bd274711ff5` | [二次 archive catalog](https://flashboot.ru/files/)。flash database、controller descriptor、sorting module を分離 |
| Solid State System | SSS MP Utility v2.162 | 1,530,494 | `329c74878f5598fcd49b29d07b86fa59b2405fc5bc15de395a35d8e82b2bdc3e` | [二次 archive catalog](https://flashboot.ru/files/)。一部 CRC error のため破損 file は根拠に不採用 |
| iCreate | i5188 AllNewChinaPD v1.5 | 306,857 | `3c67e6768d01f2e6d3891adaaab3ccaefdf9ec7acb3524d7dc2bcfa54042afff` | [二次 archive catalog](https://flashboot.ru/files/)。RAM、timing、LLF、page-scan、two-plane payload を分離。一部 CRC error |
| OTi | OTI 216X PT Multi-Device 2.9.0.23 | 799,261 | `feca686840a546c2054f2cb9b037b870635c3ccc9e195e4da768d992b67806a2` | [二次 archive catalog](https://flashboot.ru/files/)。archive は完全展開、PE は署名なし |
| Prolific | UFD Utility v21400 | 2,204,066 | `ffc5eb1af7306f38c713a6aa3bd160ca412d028d15f72076b4020b4d7eebd479` | [二次 archive catalog](https://flashboot.ru/files/)。実行 file に CRC error |
| AppoTech | DM8261 Partition V1.8 | 502,519 | `29884162f89f7a1d47e4dfc15887b093f491d2dfca21aa0692a0ad26b3ba8d25` | [二次 archive catalog](https://flashboot.ru/files/)。solid RAR を完全展開できず、listing だけを根拠に使用 |
| Ameco | MW6208E/8208 1.2.0.1 | 573,767 | `6fbf6227c34f3570c41e9ae075ae1f9d94dbef4719882488d5a3e277cbce949b` | [二次 archive catalog](https://flashboot.ru/files/)。solid RAR を完全展開できず、listing だけを根拠に使用 |
| Netac | Netac RepairTool | 425,497 | `27d9a7315ef6e576c4b779a2ae2e945be1ff6cb11ca669744ee6585a388cb444` | [二次 archive catalog](https://flashboot.ru/files/)。solid RAR を完全展開できず、listing だけを根拠に使用 |
| eFortune | eU202 MP 10.05.18 A.00.00 | 4,331,150 | `4921da6d3ea5df0ffdd402ace97326b4a156504c04ae20d13f0517e1a017e934` | [二次 archive catalog](https://flashboot.ru/files/)。preformat、run/read、die-sort、NAND organization payload を分離。一部 extraction error |

SanDisk U3 tool だけは後述する SanDisk 正規 URL の保存 response と Authenticode を確認できた。それ以外は内部 version、vendor 文書、controller 固有 loader、NAND table が相互整合する実 MP package でも、現在の配布元は vendor 自身ではなく、多くの PE に signature がない。このため「vendor 製 tool package の内容を静的解析した」という技術的根拠には使うが、archive byte 列の supply chain を正規署名済みと表現しない。CRC error、solid archive 非対応、展開失敗を生じた byte 列は production artifact や command 根拠へ採用しない。

### 追加 family の根拠と限界

- Phison の現行 [U17/U18 製品情報](https://www.phison.com/u17-u18/) は native USB 3.2 controller と 3D NAND 対応を示すが、PS2251 の version CDB 互換性は示さない。このため U17/U18 は `phison-ufd` の catalog line には含めるが、固定 PS2251 probe の対象外とする。
- ChipsBank の [CBM2199S 製品情報](https://www.chipsbank.com/product/info.aspx?itemid=10&lcid=6) と [CBM219X UMPTool manual](https://f-hauri.ch/vrac/SSD-16Tb/CB/219x/CBM219X%20UMPToolV7200%282022-04-28%29/ChipsBank%20UMPTool%20UserManual.pdf) は controller generation と量産 tool の存在を確認できるが、host service protocol は定義しない。
- Innostor の [IS917 datasheet](https://datasheet4u.com/pdf-down/I/S/9/IS917-Innostor.pdf) と [IS918M datasheet](https://www.chinaflashmarket.com/Uploads/file/2018/05/21/IS918M.pdf) は NAND channel、ECC、USB interface を確認できるが、factory command と metadata layout は公開しない。
- Hyperstone の [USB controller 製品群](https://www.hyperstone.com/en/USB-Controllers-Flash-Memory-Controllers-2124%2C%2C%2C%2Chynet.html) と [U9](https://www.hyperstone.com/en/USB-31-Controller-Flash-Memory-Controller-2129%2C%2C%2Cdetail.html) は hyMap FTL と application-specific firmware を明示する。製造 kit は [permission-controlled download](https://www.hyperstone.com/en/Download-Center-Hyperstone-1054.html) であり、公開 CDB を推測しない。
- Yeestor の [製品一覧](https://www.yeestor.com/products) は USB/SD controller を分け、YS5083/5085/5283 世代を掲載する。USB family adapter と native SD command path を混同しない。
- Trek 2000 の [ThumbDrive storage solution](https://www.trek2000.com.sg/pages/thumbdrive%C2%AE-storage-solutions) と SMSC USB97C242 の [manufacturer datasheet](https://www.mouser.com/catalog/specsheets/97c242.pdf) は legacy direct-NAND controller の存在を裏付けるが、raw NAND host command contract ではない。

AppoTech、SiliconGo、iCreate、OTi、Prolific、Ameco、Netac、eFortune、ITE、Ramos、Moai、RealWay、HuaYi、KTC などの legacy line は、二次 catalog と実 package inventory を controller namespace の根拠にした recipe-only adapter である。vendor-owned VID を一次資料で一意に確定できた family だけ candidate profile を同梱し、それ以外は接続媒体の exact OS identity と trace から production bootstrap を作る。二次 catalog の型番だけで固定 probe、service loader、NAND geometry を共有しない。

usb.ids で vendor-owned VID が一意に確定した family には `profiles/identify-*.toml` を同梱する。Trek 2000 (`0a16` Trek Technology)、Ramos (`102a` Ramos Technology)、SMSC (`0424` Microchip/SMSC) はこの条件を満たし、candidate プロファイルを追加した。FirstChip、SiliconGo、Ameco、HuaYi、KTC、Moai、RealWay は usb.ids で一意な vendor-owned VID を確認できず (例: FirstChip の `1d45` は usb.ids では "Touch" と登録)、VID ヒントなしの candidate プロファイルのみを同梱する。これらは接続媒体の exact OS identity と trace から production bootstrap を作る。

全 28 family に `profiles/identify-*.toml` を同梱した。recipe_engine と recipe_identify は全 family で true であり、bootstrap + recipe の read-controller-id / read-nand-id で識別できる。組み込みの固定識別 (`identify: true`) は一次資料で読み取り専用コマンドが確定した 5 family (Phison / Alcor / SMI / SanDisk / USBest) に限られ、残りは recipe 経由の識別となる。C3/C4 実行は recipe エンジンで全 family が同じレベルで対応し、各 family の exact production profile + runtime recipe を確定すれば有効化される。

## Phison PS2251 family

一次資料:

- [Psychson](https://github.com/brandonlw/Psychson) は PS2251-03 の version page、NAND ID、BootROM 遷移、burner 転送を実装している。README は firmware `1.03.53` と 8K eD3 NAND 以外を未検証とし、正しい NAND 固有 burner が必要で、恒久破損の可能性があると明記している。
- [Psychson PhisonDevice.cs](https://github.com/brandonlw/Psychson/blob/master/DriveCom/DriveCom/PhisonDevice.cs) は `06 05` version page、`06 56` NAND ID、`06 BF` BootROM、`06 B1/B0` 転送、`06 B3` PRAM 実行の CDB を示す。
- [flowswitch/phison](https://github.com/flowswitch/phison) は PS2303 を BootROM 化し、揮発 PRAM コードを実行する public-domain 実装である。[Phison.py](https://github.com/flowswitch/phison/blob/master/host/Phison.py) は同じ version signature と転送シーケンスを独立に実装している。
- [nand_test.py](https://github.com/flowswitch/phison/blob/master/host/nand_test.py) は XDATA register access と NAND READ ID の研究コードだが、全 NAND geometry、ECC、FBB 保護、RBB、BBT/FTL commit を実装していない。

したがって BootROM / PRAM へ入れる事実だけで D1–D4 を宣言してはならない。nclr は `BtPramCd` の exact length、header/body 512-byte chunk、各 acknowledgement、run command、entry / loader の 2 段階 USB 再列挙を実装した。残る tuple 固有情報は、burner が公開する raw page/erase/status/metadata command と response layout である。これらを静的解析と trace から authenticated recipe に固定し、NAND geometry / ECC layout と metadata format を pre-HIL check まで完成させた後、最後に HIL 認定する。

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

### PS2232 (MP2232 v1.11.0) の実ファイル解析

sdd (13fe:1f23、phison-ps2232、FW 01.05.10、NAND 2cd5943e7400) を対象に、PS2232 世代の正規 tool を追加取得した。

| 取得物 | 出典 | archive size | archive SHA-256 |
|---|---|---:|---|
| [Phison MPTool MP2232 v1.11.0](https://flashboot.ru/files/file/148/) | flashboot.ru、PS2231/PS2232/PS2233/PS2237/AE2263 対応 | 3,258,005 | 取得物を隔離した一時 directory に保存 |

archive (`Phison_PS2233-PS2237_v1.11.rar`) 内の主要 object と `nclr-lab tool --family phison-ufd` の解析結果は次のとおりである。

| object | size | SHA-256 | 解析結果 |
|---|---:|---|---|
| `MP2233_F1_B4_V111_00.exe` | 1,904,640 | `82b99c9379bf73d878cb5c7d41519ff047163bf43466fa3b95ada1a7945e73d9` | 32-bit PE (2009-04-13)。`CreateFileA/W`、`DeviceIoControl`、`setupapi.dll`、`USBSTOR` registry、`NT_GetFlashExtendID_All ScsiStatus`、`NT_GetStatus ScsiStatus`、`Read/Write ScsiStatus` を参照し、USB mass storage を SCSI pass-through で操作する。`BtPramCd`、`Burner`、`ISP`、`Preformat`、`Flash ID`、`Bad Block` の marker を検出 |
| `BBN103.BIN` | 18,944 | `d63e7c66882b829886f226dd8ce3fc7de254e124d552b461040a19ccc427d484` | `phison-bt-pram`。`BtPramCd` header、little-endian page count `18`、512-byte header + body。内部文字列は "2233 FW BURNER" — PS2233 用 burner であり、PS2232 用ではない |
| `BFF01702.BIN` | 147,968 | `332fc6bcb18968290cae0b73db8ea99dae76f379de6df50a0e72f864e539ab48` | `phison-bt-pram`。`BtPramCd` header と multi-field header (`10 10 08 00`) を持つ後期形式。burner ではなく firmware と区別される |
| `IDBLK_TIMING.dll` | 221,184 | `bcddbed92a357cc736ea03ed337d53e94fb99b749c9518b9aee88095400359d5` | 32-bit PE (2009-03-31)。`Preformat`、`Firmware` marker |
| `ParamEdt-F1-v2.1.0.2.exe` | 675,840 | `3b18ef8193203bac5c1a08adaf1f3541a44e51a3b8afdeca3cc4eb40bc239cbb` | 32-bit PE。`ISP`、`Burner`、`Preformat`、`Flash ID` marker。パラメータ編集 |
| `ParamEdt-F2-v2.1.0.2.exe` | 675,840 | `6a9872ce5a7859e569698d0705ead1fc76da40349fdca66fcd25bb7aa88fc8ab` | 同上 (F2 系統) |

追加取得: [Phison UP13 UP14 UP12 V1.96](https://flashboot.ru/files/file/10/) (2008-10-09)。PS2232 (UP13/UP14) 世代の正規 tool として解析した。

| object | size | SHA-256 | 解析結果 |
|---|---:|---|---|
| `BN206.BIN` | 25,088 | 取得物を隔離した一時 directory に保存 | `phison-bt-pram`。`BtPramCd` header、little-endian page count `96` だが実 body は 24,576 byte (expected 98,304)。内部文字列は "2231 FW BURNER" — PS2231 用 burner |
| `FF0110D.BIN` | 111,104 | 同上 | `BtPramCd` header。page count フィールドは異常値 (3,145,776) で legacy 形式ではない。後期 segmented 形式の可能性 |
| `F1_90_v196_00.exe` | 1,273,856 | 同上 | 32-bit PE (2008-03-18)。量産ツール本体 |
| `IDBLK_TIMING.dll` | 229,376 | 同上 | 32-bit PE。NAND ID / timing table |
| `ParamEdt-F1-v2.1.0.2.exe` | 643,072 | 同上 | パラメータ編集 |

UP13/UP14 ツールの burner も "2231 FW BURNER" であり、PS2232 固有の burner は確認できなかった。PS2232 (sdd) の C3 を正規 burner 経由で実現するには、PS2232 固有の burner / firmware を別途入手するか、nclr の clean-room loader を PS2232 へ適用する必要がある。

静的解析はここまでで確定する。`nclr-lab decode` が表示する `06 05` version page、`06 56` NAND ID、`06 BF` BootROM、`06 B1`/`06 B0` transfer、`06 B3` PRAM run は PS2251 系の公開実装 (Psychson / flowswitch) と一致するが、PS2232 世代で同一 CDB が使われることを確定するには、MP2232 を実媒体に対して実行した USB BOT capture と成功／失敗 trace の差分が必要である。PC110.TXT の内容も recipe 作成時に追記する。

PS2232 の C3 を有効にするには、この archive の burner / firmware / timing と、同一 tool / device tuple の USB trace から確定した loader 遷移、raw page/erase/status、BBT/FTL/capacity commit を 1 個の runtime recipe に固定し、pre-HIL check を通す必要がある。現在は静的解析のみ完了で、HIL 前の trace / recipe は未完了である。

### PS2232 の USB trace 検証 (MP2232 GetInfo)

KVM 上の Windows 10 で MP2232 v1.11.0 の `MP2233_F1_B4_V111_00.exe` を実行し、sdd (13fe:1f23) を USB パススルーして GetInfo を実行した。ホスト側 usbmon でキャプチャした pcapng から CBW/CDB を抽出した結果、GetInfo は次の読み取り専用コマンドを送信していた。

| CDB | 意味 | nclr 実装との一致 |
|---|---|---|
| `06 05 00 00 00 00 00 00 80 00 00 00` (dtl=528) | Phison version page | `phison_version_cdb()` と一致 |
| `06 05 49 4E 46 4F 00 00 80 00 00 00` (dtl=528) | version page ("INFO") | 同上 |
| `23 00 00 00 00 00 00 00 fc 00` | READ FORMAT CAPACITIES | GetInfo の容量取得 |
| `12 01 80 00 ff 00` | INQUIRY VPD 0x80 | 標準 |
| `25 00 ...` / `28 00 ...` | READ CAPACITY(10) / READ(10) | 標準 |

`06 05` の 528 バイト応答を pcapng から復元し、`VR` シグネチャ (0x17A)、chip type `2232` (0x17E)、firmware `01.05.10` (0x94)、mode `firmware` を確認した。これは nclr が実機から直接取得した version page とバイト単位で一致し、`nclr-lab decode` も同じ CDB を PHISON VERSION PAGE として認識する。したがって、MP2232 ツールの読み取り専用識別経路は nclr の `06 05` 実装と同一プロトコルであることを実機 trace で確定した。

## Alcor AU698x

一次資料:

- [alcorhack](https://github.com/tizbac/alcorhack) は作者の AU698x リバースエンジニアリング実装である。
- [作者の調査記録](https://linuxehacking.ovh/2014/07/20/alcor-ufd-controller-hacking-update-2/) は `82 51 01` による 512-byte config read と `81 00 ff` による config upload を説明するが、実験段階である。
- [main.cpp](https://github.com/tizbac/alcorhack/blob/master/main.cpp) は `FA 00` flash-ID read と物理 sector read の研究経路も含む。ただし、準備 blob の意味、geometry、ECC、消去、BBT/FTL commit は確定していない。

実測 (PQI Traveling Disk U273、VID `3538`、OEM VID): `82 51 01` config read は GOOD だが 0 バイト (config page 非実装)、`FA 00` flash-ID read は 512 バイトの NAND ID `89 68 04 46 A9 00` を返す。nclr は config page が無い世代でも `FA 00` の有効な 6-byte NAND ID から `alcor-ufd-<nand_id>` と識別する。このフォールバックは VID ヒントなしのデバイスに対しても試行される。ただし、UT163 (Imation Flash Drive Mini) では `FA 00` が CHECK CONDITION を返さず 60 秒の DID_TIME_OUT で USB reset に至ることを URescue trace 検証の際に確認した (後述)。nclr は USBest の marker パスを vendor CDB より先に試行するため、profile が配備された環境では `FA 00` を送らない。識別は読み取り専用の情報提供であり、config page が無い世代の destructive capability は公開しない。

### PQI U273 の USB trace 検証 (AlcorMP)

KVM 上の Windows 10 で AlcorMP v13.10.28.01.C を実行し、sdb (3538:0901) を USB パススルーして Refresh を実行した。ホスト側 usbmon でキャプチャした pcapng から CBW/CDB を抽出した結果、AlcorMP は次の読み取り専用コマンドを送信していた。

| CDB | 意味 | nclr 実装との一致 |
|---|---|---|
| `82 51 01` (dtl=512) | Alcor config read | `alcor_config_read_cdb()` と一致 |
| `fa 00` (dtl=512) | Alcor flash ID | `alcor_flash_id_cdb()` と一致 |
| `12 01 80` (dtl=252) | INQUIRY VPD 0x80 | 標準 |

`82 51 01` の 512 バイト応答を pcapng から復元し、`99 07` シグネチャ、VID `3538` (offset 12)、PID `0901` (offset 14)、bcdDevice `0100` (offset 16)、USB 文字列 "PQI" / "PQI USB Flash Drive" / "Generic USB Flash Disk 8.01"、シリアル "02AA0000000000000000000284" を確認した。nclr の `parse_alcor_config` はこの実機応答を `alcor-au698x-3538:0901` (firmware 0100) として正しく解析する (ユニットテスト追加済み)。

AlcorMP 自体は Refresh で一覧にデバイスを表示しなかった。これは AlcorMP が config 応答の controller type (offset 2-3 の `08 28`) を内部の既知リストと照合するためで、nclr 側の識別コマンド送信・応答解析は実機 trace で正常であることを確定した。

`0x81` はソース中で rebuild と呼ばれる箇所があるが、確認できる効果は USB 設定の upload / regenerate であり、D1–D4 の完全消去を意味しない。nclr はこの write CDB を hard-code しない。正規 tool trace で物理 erase、raw page、status、BBT/FTL commit の個別 semantics が確定した exact tuple だけを Alcor recipe として実行できる。

### AlcorMP 実ファイル解析

archive 内の `AU698X MP user's manual_Chinese.pdf` は Alcor Micro International / 群勝科技名義、作成日 2013-04-25、SHA-256 `b9a3890313b8e16e90ebe95ca21bdda6bd826b147f613edd5d72c2a0dad754a7` である。本文は最大 16 台、Flash ID / CE / channel 自動識別、raw bad-block marker 読み出し、全 block への write/read compare、全情報消去、旧 MP bad-block 情報の再利用、予約 block、ECC 0–15、full / quick scan を明記する。これは D1–D4 相当機能が実 tool に存在する直接の vendor 文書である。

`AlcorMP.exe` は 2013 年 10 月 build、SHA-256 `32d90a6b07282cf2010635897a3680f8cf79171bb66bb21313aa5994c46aaee2`、`UfdApi_Gen.dll` は SHA-256 `a295ca70372edbbc59f3d33a7ff91e32a177b0240889d5633f9f67397421a6b1`、`UfdComLib.dll` は SHA-256 `0c1c1b2020892675add4b55b94399cf487290cb2b4b8c3d4e7cbccf4005043b3` で、いずれも署名されていない。構成は次のように分離されている。

- `UfdCom/CTL/10/10_GEN.BIN`: controller generation code。ASCII hex 化された 8051 code。
- `UfdApi_Gen/CTL/10/BIN/*.BIN`: NAND family 別 low-level code。
- `SCAN_BIN/*_SCAN.BIN` / `*_SORT.BIN`: raw scan / bad-block sort code。
- `FlashList.ini` / `FlashList.dat` / encrypted `flashlist.afl`: 6-byte Flash ID、driving level、NAND 固有設定。
- `LLF.dll`: 1.5 MiB の opaque LLF payload。通常 PE DLL ではない。

schema 2 の構造解析では、top-level `FlashList.ini` から `89d3902e6452` / `JS29F08G08AANC1` と `ec79a5c00000` / `K9K1G08U0M/A/B` の 2 個の exact FID を取得した。`UfdApi_Gen/CTL/10/FlashList.ini` からは 306 個の module 行を 8／9 個の raw integer parameter として保持し、109 参照を package 内 BIN へ一意解決した。残る 197 参照は package にないため `missing` とし、似た file 名へ置換しない。合計 124 file を controller GEN、NAND operation、die-grade、scan/sort、database role として SHA-256 付き inventory にした。parameter の意味は vendor format で確定していないため、数値を geometry field として解釈していない。

`UfdApi_Gen.dll` は page mapping、original / current bad block、physical page、reserve block、scan pattern、EraseAfterMP、BBT read/write failure を個別に扱う。したがって `82 51 01`、`FA 00`、`81 00 FF` の 3 command だけを hard-code しても正規処理にはならない。controller code と NAND scan code の upload sequence、response signature、BBT / reserve metadata commit を capture から recipe 化する必要がある。

ALCOR U2 MP v20.09.16.00 も追加取得し、2013 年版の分離構造が 3D NAND 世代でも維持されることを確認した。`AlcorMP.exe` は version 3.1.1.33、548,864 byte、SHA-256 `7e4eda0629333e7921c5f73a8300de6d959cf25eb34c0fa626eaa16357770362`、`UfdApi_X3.dll` は 1,736,704 byte、SHA-256 `52c06d1ce3537e431f72d226bfc05a8dc0b6180d72030d0fc47be9c2d32a8340`、`UfdComLib.dll` は SHA-256 `0f215cc08232232d7dbddee85d6a9e8adbff68d337f6add140ea44f1d6e85f01` で、全て署名なしである。2019 年版 vendor manual は SHA-256 `1bce74e048acdf8d6878d7613e59ccc97a3b5be0c7e5e0059e3d5631f7ceb1d7`、2020 年 change log は SHA-256 `14454f9cfa0db097a92407e6c65236ede5c08e14629538eaa4f7f8c8f018b3e7` である。

後期 package は `CTL/28` の controller code、NAND 別 `BIN`、diagnostic `DGD_BIN`、physical scan / low-level format 用 `SCAN_BIN`、`SORT_BIN`、short / long bootloader、opaque `LLF.dll` を分離する。change log は AU6989SN-TA／GTC／GTD／GTE、Toshiba／SanDisk Gen4.5、Micron／Intel B16A／B17A／B27A／N18A／N28A、Samsung、Hynix、YMTC を個別に扱い、古い controller や古い MP との high-level format 互換性がない組み合わせも明記する。従って Alcor も `AU698x` という 1 recipe ではなく、controller generation + full NAND ID + selected BIN / SCAN loader の exact tuple が必要である。

## Silicon Motion

製品一次資料で確認できるのは controller 能力までである。これとは別に、公開された Linux `sg_raw` transcript から読み取り専用 identity page の 1 command だけを clean-room 実装した。

- Silicon Motion の [SM3267 発表](https://ir.siliconmotion.com/news-releases/news-release-details/silicon-motion-introduces-sm3267-ultra-high-performance-cost) は NAND 種別、性能、量産向け turnkey solution を説明するが、service CDB は公開しない。
- [SM3282 product brief](https://www.siliconmotion.com/download/p/a/SM3282_PB_EN_201910.pdf) は UASP、NAND channel、ECC、turnkey firmware を説明するが、物理消去・BBT/FTL 再構築のホストプロトコルは公開しない。
- [公開調査記録](https://sstahlman.blogspot.com/2021/) は `sg_raw -r 1024 ... f0 04 00 00 00 00 00 00 00 00 00 02` と、offset `0x20` の `2013-02-26  SM3257ENLTBA   SMI32X` response を掲載している。nclr は transfer 1024 byte、printable ASCII、日付、`SM3...` part、`SMI32X` signature を全て検査し、identity にだけ利用する。
- SD controller については [SM2707EN product brief](https://www.siliconmotion.com/download/3PN/a/SM2707EN_PB_EN.pdf) が標準 SD full-user-area logical erase を記載する。しかし、これは D0 の標準論理範囲であり、D1–D4 の vendor service protocol ではない。
- native SD の標準経路は旧 SDSC も扱う。[Linux MMC core の `mmc_do_erase`](https://github.com/torvalds/linux/blob/master/drivers/mmc/core/core.c) と [SD CSD parser](https://github.com/torvalds/linux/blob/master/drivers/mmc/core/sd.c) に合わせ、CSD structure 0 は CMD32/CMD33 の sector start を 512 倍した byte address、structure 1/2 は block address とする。CSD の erase command class 5、kernel が公開する erase group、全 user range の group alignment と 32-bit argument 境界を probe と run の両方で再確認する。これは D0 の standard erase 対応であり、SD 内部 controller の C3/C4 対応数には含めない。

`F0 04` 以外の bounded destructive command、response signature、失敗時復旧は公開資料から確定できない。特に `0x2a` parameter への言及だけから CDB layout を作らない。メーカー資料、再配布可能な SDK、または所有する犠牲媒体と正規 MPTool の USB trace から確定した command は、SMI recipe engine へそのまま投入できる。

### SM3257ENAA MPTool 実ファイル解析

`sm32Xtest_V58-8.exe` は version 2.3.58.8、build timestamp 2011-11-29、2,240,512 byte、SHA-256 `82ebcc3b9502452638f74a7449d6cb95bdd4abd90f3ce9284ebed7e0d4902845` である。PE version resource は `Silicon Motion Technology Corp.` と copyright 2011 を保持するが、security directory は空である。同梱 release note は `SMI CONFIDENTIAL`、作成日 2011-11-30、SHA-256 `010e8e66bc63d1fdcd695654943ba062c10f230723400690eefe9671a23b7dd9` で、SanDisk 24 nm MLC read-retry table、system block erase、original bad-block scan、full ISP write、ISP checksum を version ごとに説明する。

package は SM3254AE / SM3255AB / SM3255ENA1 / SM3257AA / SM3257ENAA / SM3260AB ごとの `.dbf` と ForceFW mapping、NAND vendor / generation ごとの ISP / pretest、CardMode boot image を分離している。

- `flash_3257ENAA.dbf` は 24,813 byte、SHA-256 `4b317d1fca8cab579f9b9a84c15aa53642943c364dd46d22d3a50fa9e93a8d29` で、6-byte Flash ID と geometry / timing / ECC parameter を持つ text table である。
- `SM3257ENAA.FFW` は 11,621 byte、SHA-256 `1e99ce14d18e6832f19b75bdc03165fbdf562dcbe49962e3611d6ab3b3b4b6ba` で、完全な Flash ID ごとに ISP と PTEST を選ぶ。
- default `SM3257ENAAISP.BIN` は 71,680 byte、SHA-256 `49da877e11c49624773894ac1e7e872eda88a6816a2b644c7f4c153fbb26d1a6`、header 内に `SM3257ENAA` と firmware `111123-AA-` を持つ。
- `SM3257ENAAPTEST.bin` は 24,576 byte、SHA-256 `cd39a2f34100df1742bb65773a1b3a893f85d40c1408da483eace30731237486` で、original bad block を検出する pretest code である。

schema 2 の構造解析を展開 tree 全体へ適用すると、6 controller map から 154 個の exact NAND binding を得た。対象の `smi-sm3257enaa` だけでは 71 個の完全な 6-byte NAND ID と 142 個の ISP / PTEST 参照があり、142 個全てを package 内の 1 file + size + SHA-256 へ一意解決した。他 controller 用 map の参照 168 個はこの SM3257ENAA 配布物に存在しないため `missing` のままであり、別世代 artifact へ暗黙 fallback しない。

main tool は Info Block と backup、ISP block、spare、erase count、original/new bad block、CE / plane / block / page、ECC、read-retry を区別する。これも host の単一 erase CDB ではなく、Flash ID で選んだ NAND-specific ISP / pretest を controller へ導入して処理する構造である。nclr の `F0 04 00 00 00 00 00 00 00 00 00 02` はこの package と同じ SM32X family を識別するが、NAND ID ではないため、`nclr-lab decode` でもその境界を明示する。

Dyna SM3281 series U0204 も追加取得した。`SMIMPTool.exe` は version 21.2.1.1、3,588,096 byte、SHA-256 `e5d95716610c173a5f11b655e53ef39a5dde5f8f81ee9df5b94cdf65c7c1a5f7`、署名なしである。一方、`PretestGP3265_U0203V1.dll` は Silicon Motion Inc. metadata を持つ version 21.2.3.1、SHA-256 `464381a2b9164834e6547c9cb9bf0b066bb9b5c8ec684d50ddcdab27de97f63e`、`PretestGP3271_U0115V2.dll` は version 21.1.15.2、SHA-256 `43870049820bad7a024e182bce59520fc400338d86c40ffc83b93a0639e53dc3` である。

package は SM3265AB、SM3271AB／AD／BA、SM3281AB／BA／BB ごとの `.FFW`、SM3265AB／SM3271AB／SM3281AB／BB ごとの `.dbf`、1,886 個の NAND / ISP / pretest `.bin`、211 個の `.ebi`、controller 別 read-retry table を分離する。例として `SM3265AB.FFW` は SHA-256 `a6d7cbde3eab116491f0116d69b91ece6bf1999809b730d595556af60f4bfca4`、`SM3271BA.FFW` は `3e68061e965d9a08c1f08c80354bbdb126d93e5bc461d5be814261765e2a65b5`、`SM3281AB.FFW` は `282d96c219f280a798f33a7fb13cc38eee3f71ba1fc43af43b363b0a9419c1da` である。pretest module の文字列は system page/block、original page count、ISP block count、backup page、remapping、SLC/TLC spare pool、ECC 144、read-retry table、multi-CE / plane を個別 field として扱う。

schema 2 の全 tree 解析では 7 controller generation、1,835 個の exact NAND binding、451 個の read-retry table を抽出した。146 binding は同一 key に複数の active value を持つため selection ambiguity を明示したままにする。同名 artifact が複数 path にある場合も、全候補の size と SHA-256 が一致するときだけ `identical-content` とし、異なる byte 列を 1 個へ縮約しない。この静的 binding により NAND ID から候補 ISP / retry / sorting / generic-info 部品までは実機なしで絞れるが、FFW の競合を解消する追加条件と controller への upload / execution protocol は別途確定が必要である。

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

1.0.2.36 は RAR SFX であり、内部の実処理 PE `LPInstaller.exe` は 1,733,944 byte、SHA-256 `26a0aef18db3da91c594f1650e657d4d89181ae02ca76a4e9b2cb0f58b837cf3` である。`nclr-lab tool --family sandisk-cruzer` をこの PE へ適用すると、offset `0x80a21`、`0x91dde`、`0x91ea7`、`0x92460`、`0x92610`、`0x927b0`、`0x92950`、`0x92f30`、`0x9320e`、`0x932df` 付近から 10 個の dynamic x86 constructor candidate を抽出した。命令列は `push 0; push 0xff; push direction; push opcode; push length; call constructor` で、opcode は `25`、`20`、`21`、`22`、`23`、`24`、`25`、`40`、`41`、`42` である。tool 出力はこれらを logical-domain / CD / private configuration と分類し、`production_eligible = false` を固定する。

[Debian u3-tool 0.3-4 の `u3_commands.c`](https://sources.debian.org/src/u3-tool/0.3-4/src/u3_commands.c/) は 13,813 byte、取得 byte 列の SHA-256 は `2f005d2ace03818a74ed05a23517c55c6a311cde0dad55d894bd1c264270a5bc` である。source literal analyzer は `FF 22` と `FF 03 01` を直接検出し、同 source に定義された `FF 00`、`20`、`21`、`42`、`A0`、`A2`、`A3`、`A4`、`A6`、`A7`、`01 01` も logical property / domain / CD / security / reset として分類する。正規 binary の constructor と独立した公開 source が同じ command family を示すため、これらを raw NAND command と解釈する余地はない。

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

このため engine の bounded grammar は `82-00263-1` を含む SanDisk proprietary controller recipe を表現できるが、現時点でこの marking の媒体に送信できる raw NAND recipe は repository にない。未確認 PID、firmware、CDB、geometry を埋めた profile も同梱しない。対象個体の正規 tool capture から exact `read-controller-id`、`read-nand-id`、physical erase / raw page / status / BBT / FTL commit command を抽出し、同一 tuple の pre-HIL recipe として固定する必要がある。HIL はその後の最終認定であり、これらの command を取得する前提ではない。

## USBest UT163

一次資料:

- [USBest UT163 datasheet](https://opendevices.ru/wp-content/uploads/2011/11/USBest_UT163.pdf) は USB 2.0 flash disk controller の機能を説明するが、SCSI ベンダー固有コマンドや service mode の protocol は公開しない。
- [UT163/UT165 USB Flash Disk Utility の user manual](https://archive.org/details/manualzilla-id-5806917) はパーティション、boot disk、secret area の使い方を説明する Windows ツールの説明であり、ホスト protocol 定義ではない。
- usb.ids は `4146` を "USBest Technology" に、`1307` を "Transcend Information, Inc." に登録するが、USB-IF の registry 議論は `1307` を USBest Technology Inc. の割り当てとする。いずれも識別のヒントに過ぎない。

実測 (Imation Flash Drive Mini、VID `0718`、UT163 搭載): 標準 INQUIRY を 96 バイト要求すると、36 バイトの標準データを超える vendor-specific 領域に `UtffU163A1BM` のマーカーが返る。`profiles/identify-usbest-ufd.toml` が vendor-owned VID ヒント (`4146`、`1307`) と INQUIRY マーカー (`U163`) を宣言し、nclr はこの領域のパターンを検証して controller ID `usbest-ut163` を返す。この識別は標準 INQUIRY だけを使い、未知の vendor CDB を送信しない。UT165 以降はこの marker probe の対象ではない。全 USBest line は common recipe adapter を利用できるが、exact service CDB、NAND identity、metadata format と HIL がない状態では destructive capability を公開しない。

### URescue v1.3.0.71 の USB trace 検証 (UT163)

KVM 上の Windows 10 で URescue v1.3.0.71 (USBest UT161/UT163/UT165/IT1167 専用の recovery / update tool、SHA-256 `9b390185...`) を実行し、sdc (0718:0084) を USB パススルーして Update を実行した。ホスト側 usbmon でキャプチャした pcapng (`urescue-trace.pcapng`、EPB 76552 件、dev 6 = Imation Flash Drive) から CBW/CDB を抽出した。

**識別 (read-only) フェーズ** — Update の前に URescue が送信した読み取り専用コマンド:

| CDB | dtl | 応答 | 意味 |
|---|---|---|---|
| `fd 10 00...` (12B) | 5 | `2c d3 94 a5 e5` | NAND ID (5 byte) |
| `f2 00...` (12B) | 35 | 35 byte status | 状態取得 |
| `f8 00 00 00 00 00 00 00 01 00` | 2048 | firmware 領域 | addr 0x0000 の 2048B read |
| `f8 00 00 02 00 00 00 00 01 00` | 2048 | 同上 | addr 0x0200 |
| `f8 00 00 04 00 00 00 00 01 00` | 2048 | 同上 | addr 0x0400 |
| `f8 00 00 06 00 00 00 00 01 00` | 2048 | 同上 | addr 0x0600 |
| `fd 00 00 41 13 00 00 02 00` | 512 | config 領域 (0x4113) | 512B read |
| `fd 00 00 00 03 00 00 00 01 00` | 512 | config 領域 (0x0003) | 512B read |
| `fd 00 00 00 4a 00 00 00 01 00` | 512 | config 領域 (0x004a) | 512B read |
| `fd 00 00 46 da 00 00 00 01 00` | 512 | 乱数様 (0x46da) | 512B read |
| `fd 0e 00...` (10B) | 512 / 1536 | ゼロ | サブコマンド 0x0e read |
| `f3 00...` / `f6 00...` (6B) | 1 | 1 byte | status probe |

`fd 10` の 5 byte NAND ID 応答、`fd` の 512 byte config read 応答を pcapng から復元し、reference binary として保存した (`usbest-fd10.bin` ほか)。`fd 00 00 41 13` 応答には `ffff 5555` のマーカーと物理 block 対応表らしき増加列、`fd 00 00 00 03` 応答には NAND 容量・ページ構成らしき値が含まれ、`f8` の 2048B read は 8051 命令列 (`90 00 07 e0` = MOV DPTR/MOVX) を含む firmware コード領域である。

**Update フェーズ** — `fd 13 01` (OUT, dtl=0) で update mode に入り、`fd 00 01 00 4c 88` (OUT) を送った後:

| CDB | dtl | 意味 |
|---|---|---|
| `fd 00 00 f0 00 00 00 02 00` / `fd 00 01 f0 00 00 03 02 00` | 512 | 0xf000〜0xfe00 の 8 block を read-modify-write (byte2 の 0x00=read / 0x01=write) |
| `fd 11 00...` (OUT) | 0 | commit / execute |
| `fe 00 00 <addr> 00...` | 1 | status / progress poll。address フィールドが 0x0000 から順に増える (3940 回) |
| `fa 00 00 <addr> 00 00 00 02 00` (OUT) | 4096 / 65536 | page write (address は 0x0200 刻みで増加) |
| `f8 00 00 <addr> 00 00 00 02 00` | 4096 | page verify read |
| `f2 00...` | 35 | status |
| `fd 0f 00...` (OUT) | 512 | 最終化 |

各 page write の後には TEST UNIT READY (`00`) + REQUEST SENSE (`03`, 18/24 byte) の連打が挟まり、`fa`/`f8` のペアで書込→読戻し検証をしながら address を進める。最後に標準 SCSI の `28` (READ) / `2a` (WRITE) で論理領域を検証し、`1e` (PREVENT ALLOW MEDIUM REMOVAL) で終了する。update 後の論理容量・識別子は変化していない。

これにより UT163 の vendor protocol は `fd` (read/write/config, サブコマンド 0x10=ID, 0x0e=read, 0x0f=finalize, 0x11=commit, 0x13=update mode)、`f8`/`fa` (page read/write)、`f2` (35B status)、`f3`/`f6`/`fe` (1B status) で構成されることが確定した。ただし `fa` の page write が raw NAND page か FTL 経由か、BBT / reserve 領域の commit 規則は trace だけでは確定できず、nclr はこの trace で観測された read-only コマンド (`fd 10`、`f2`、`f8`、`fd` read) を識別にのみ利用し、write 系 (`fd 13 01`、`fa`、`fd 11`、`fd 0f`) を hard-code しない。

Update 適用後 (sdb として再接続) に `nclr info` で再検証した。INQUIRY の `UtffU163A1BM` marker、Vendor/Product `Imation` / `Flash Drive`、論理容量、fingerprint は変化していない。識別は profile 配備時 (`NCLR_PROFILE_DIR` または `/usr/share/nclr/profiles`) に marker 経由で `usbest-ut163` を返す。ただし profile 未配備の環境では VID ヒントが無いため Alcor `FA 00` フォールバックが試行され、URescue 適用後の本機は `FA 00` に DID_TIME_OUT (60 s) で応答し USB reset に至ることを確認した。適用前の同一コマンド応答は記録が無いため、この挙動が firmware update 由来か否かは未確定。profile を配備して marker 経由で識別すれば vendor CDB を送らず、この問題を回避できる。

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

プロファイル検証もこの境界を強制する。`trust = "validated"` の real profile に `nclr-lab profile --check --pre-hil --artifact-dir STORE PROFILE` を適用すると、firmware / NAND の完全一致、D1–D4 accounting、BBT / FTL / spare rebuild、`protected_area_bytes`、`logical_blank_value`、clean-room / runtime provenance、protocol trace、exact NAND geometry、FBB marker、randomizer / read-retry / ECC layout、BBT / FTL / spare format、atomic commit、system block policy、runtime recipe、全 non-HIL artifact の実 byte 検証を要求する。recipe は parse だけでなく crash / re-enumeration、response、address field、metadata layout まで意味検証される。

`trust = "production"` への最終昇格で初めて、独立 HIL report の SHA-256、reader 名、sample 数、power-cut case 数を追加する。この分離により、HIL 不在を理由に command 解析や pre-HIL 実装を未完了のまま残せない一方、HIL のない profile が purge capability を自己申告することもできない。recipe schema と crash / re-enumeration 契約は [`controller-protocol-recipe.md`](controller-protocol-recipe.md) に記載する。`simulated = true` は組み込み `sim-controller-1` 以外では拒否される。
