# コントローラー取得物とクリーンルーム解析

## 目的

28 系統の登録済み USB flash controller family に必要な量産 tool、service loader、USB capture は nclr に再配布しない。代わりに、利用者が正当な入手元から取得した完全一致 byte 列を manifest で固定し、content-addressed store へ格納する。controller backend は path を受け取らず、core が検証して開いた read-only FD だけを継承する。

この仕組みは vendor tool が存在することを D1–D4 到達の証拠に変換するものではない。実装 provenance、NAND geometry、metadata layout、電源断 recovery、独立 HIL report がすべて揃うまで、実媒体の `CONTROLLER_REINITIALIZE` capability は無効のままである。

## 一次資料と実装根拠

- USB Mass Storage Bulk-Only Transport の CBW / data / CSW は [USB-IF Bulk-Only Transport 1.0](https://www.usb.org/sites/default/files/usbmassbulk_10.pdf) に従う。
- Wireshark の raw USB payload field は [`usb.frame.data`](https://www.wireshark.org/docs/dfref/u/usb.html) である。`usb.capdata` は padding field であり、protocol 抽出には使わない。
- offline 変換は [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) を subprocess として使う。
- Phison の `06 05`、`06 56`、`06 BF`、`06 B1`、`06 B0`、`06 B3` と `BtPramCd` layout は [Psychson](https://github.com/brandonlw/Psychson) および public-domain の [flowswitch/phison](https://github.com/flowswitch/phison) で相互確認した。
- Alcor の config / flash ID 経路は [tizbac/alcorhack](https://github.com/tizbac/alcorhack) で確認した。公開実装の config write は物理 erase、BBT rebuild、FTL commit を証明しない。
- Silicon Motion の公開 [SM3282 product brief](https://www.siliconmotion.com/download/p/a/SM3282_PB_EN_201910.pdf) は controller capability を説明するが、service CDB は定義しない。公開された `sg_raw` transcript の `F0 04 ... 02` identity page は読み取り専用識別にだけ実装し、未公開の erase / NAND command は推測しない。
- SanDisk Cruzer `82-00263-1` は board marking と NAND の組み合わせまでは複数の実基板情報で確認できるが、固定 service CDB は公開されていない。正規 tool capture の先頭から、媒体変更前に controller / firmware と NAND ID を返す command を特定し、それぞれ `read-controller-id` と `read-nand-id` に固定する。USB VID `0781` や SCSI product 文字列だけでは command を replay しない。同じ exact bootstrap は OEM VID の Phison / Alcor / SMI にも使えるが、profile に family を明記し、runtime の 2 段 identity が一致するまで capability を有効にしない。

実 tool の静的解析では、Phison MPALL は `BtPramCd` burner と ID block/timing table、SM3257ENAA MPTool は controller 別 DBF / ForceFW と NAND 別 ISP / PTEST、AlcorMP は controller GEN code と NAND 別 scan/sort code を分離していた。FirstChip、ChipsBank、Innostor、SSS、iCreate、OTi、eFortune の package でも controller/NAND 別の external code、scan、preformat、ISP、timing、low-level-format、BBT/FTL 相当 payload が分離されていた。したがって factory-tool archive や PE 全体を backend で実行する設計にはしない。取得環境で次の単位へ分離し、それぞれ exact size / SHA-256 と hardware tuple を manifest に固定する。

- controller へ転送する loader / ISP / pretest code
- Flash ID と geometry / timing / ECC の table
- USB capture から確定した command recipe
- loader が返す response signature と BBT / FTL / reserve metadata layout

二次 archive しか入手できない tool は、内部 vendor metadata が整合しても正規署名済みとは扱わない。manifest の `source_url` は実際に取得した object、`terms_url` は vendor の適用条件を記録し、hash が異なる別 build を同じ artifact id で置換しない。

## Artifact manifest

manifest は再配布物ではなく、取得する byte 列の identity と利用条件を固定する metadata である。

```toml
schema = 1

[artifact]
id = "ps2303-010353-example-burner"
role = "service-loader"
kind = "service-loader"
format = "phison-bt-pram"
controller_id = "phison-ps2303"
firmware = "01.03.53"
nand_id = "98de94827656"
sha256 = "<64 lowercase hex characters>"
size_bytes = 33280
source_url = "https://<authorized-source>/<exact-object>"
terms_url = "https://<authorized-source>/<terms>"
redistributable = false
```

対応する `kind` / `format` は次のとおりである。

| kind | format | 追加検証 |
|---|---|---|
| `service-loader` | `phison-bt-pram` | 旧 `BtPramCd`、1 KiB page count、exact length、bounded chunk layout |
| `service-loader` | `phison-bt-pram-extended` | 後期 MPALL segmented `BtPramCd`、512-byte alignment、zeroed reserved header、non-uniform body、bounded chunk layout |
| `factory-tool-executable` | `portable-executable` | PE `MZ` signature |
| `factory-tool-archive` | `archive` | ZIP / RAR / 7z signature |
| `geometry-table` | `json` / `toml` | syntax と top-level object / array |
| `protocol-recipe` | `json` / `toml` | schema、exact hardware tuple、固定 CDB、response signature、全 transfer / metadata 境界 |
| `protocol-trace` | `pcapng` | pcapng section-header signature |
| `qualification-report` | `json` | syntax と top-level object / array |

`opaque` は format を確定できない研究 artifact に限る。production profile の意味検証を省略する指定ではない。

MPALL 5.13 の `2261PRAM`、`2307PRAM`、`2309PRAM` は、旧 burner の 1 KiB page-count header ではなく segment descriptor を持つため `phison-bt-pram-extended` を使う。通常 firmware も同じ `BtPramCd` marker と類似 header を持つので、marker や file 名だけでは loader と認定しない。factory package 内で PRAM として選択された exact object の size / SHA-256、対象 controller / firmware / NAND tuple、USB trace の全てを manifest と profile へ固定する。

## 取得、import、検証

vendor byte 列は nclr の build artifact に含めない。

```sh
# HTTPS 取得。非再配布 artifact は terms URL を確認して明示同意する。
cargo run -p nclr-core --bin nclr-lab -- \
  artifact fetch artifact.toml \
  --store "$PWD/controller-artifacts" \
  --accept-source-terms

# Browser や正規 installer で取得済みの byte 列を import する。
cargo run -p nclr-core --bin nclr-lab -- \
  artifact import artifact.toml downloaded.bin \
  --store "$PWD/controller-artifacts"

# 取得元を実行せず再検証する。
cargo run -p nclr-core --bin nclr-lab -- \
  artifact verify artifact.toml \
  --store "$PWD/controller-artifacts"
```

fetch は user の `.curlrc` を無効化し、HTTPS のみ、HTTPS redirect のみ、TLS 1.2 以上、connect 30 秒、全体 900 秒、redirect 5 回、manifest の `size_bytes` 上限で `curl` を起動する。その後に size、SHA-256、format を別途検証する。保存先は `<store>/<id>/<sha256>` であり、既存 object を上書きしない。非再配布 artifact は `--accept-source-terms` なしで取得できない。

`nclr run` / `nclr resume` は `--artifact-dir` を複数指定できる。`NCLR_ARTIFACT_DIR` は platform の path separator で複数 store を指定できる。plan が固定した artifact が 1 つでも欠ける、変化する、または profile の要求が plan 時点から変わった場合は、確認前に停止する。

```sh
nclr run --plan media.plan.json \
  --artifact-dir "$PWD/controller-artifacts"
```

core は artifact を `O_NOFOLLOW` で開き、再検証後に `artifact:<id>` role の連続 FD として backend へ渡す。backend も inherited FD を再度 hash / size / format 検証する。run、status、recover の間で同じ FD を保持するため、path 置換は実行 byte 列を変えない。

protocol recipe は profile と独立にも完全検査できる。profile 内の exact size / SHA-256 を先に検証するため、単に parse できる別 recipe への差し替えは通らない。

```sh
cargo run -p nclr-core --bin nclr-lab -- \
  recipe --profile exact-production.toml --file exact-recipe.json
```

recipe の契約は [`controller-protocol-recipe.md`](controller-protocol-recipe.md) に記載する。

## 未対応媒体からの情報収集

実 USB flash drive を接続した最初の操作は読み取り専用の `info` である。

```sh
nclr info -j /dev/diskN > controller-inventory.json
```

macOS では `diskutil` と IOKit registry を結合し、対象 BSD whole disk の provider chain にある exact USB VID、PID、bcdDevice、manufacturer、product、serial、location ID と SCSI vendor、product、revision を取得する。multi-LUN device では対象 BSD node の経路だけを検索し、兄弟 LUN の SCSI tuple を混入させない。OS identity 取得だけでは media command を送信しない。

JSON の `controller_research` は、selection 根拠、候補 family、観測した exact bootstrap、identity source、実際に送信した read-only command 一覧、production 化に不足する証拠を返す。VID だけで選ばれた family は候補にすぎず、未知 vendor command は送信せず capability も公開しない。固定 probe が利用できない macOS でも、この bundle から exact bootstrap profile の作成、正規 tool trace の対応付け、追加調査の不足項目を再現できる。

この出力には USB serial が含まれるため、外部共有前に取り扱いを決める。ただし production bootstrap では serial の空文字も wildcard ではなく exact absence として扱い、識別強度を下げる暗黙 fallback は行わない。

native SD では同じ `info -j` が command-free の `sd_research` を返す。Linux の MMC registry から取得できる CID、CSD、SCR、manufacturer/OEM ID、product、serial、製造日、host、card kind、erase group を complete / partial に分類し、macOS で card register が公開されない場合は `os-identity-only` と明示する。CSD の address structure と erase command class から、SDSC の byte-addressed または SDHC/SDXC/SDUC の block-addressed standard full-user erase が protocol 上成立するかも事前計算する。CID/CSD/SCR は card identity であって内部 controller / firmware identity ではないため、vendor service command、NAND geometry、page/OOB addressing、BBT/FTL metadata、loader、recovery と HIL 証拠を別の不足項目として保持し、C3/C4 capability へ変換しない。

## USB BOT trace の抽出

正規 factory tool が動作する隔離済み環境で USB capture を pcapng として保存する。capture には媒体 user data、serial、鍵、credential が含まれる可能性があるため、公開してはならない。Mac では Wireshark を install して offline 解析だけを行える。Linux 実機検証は不要である。

```sh
cargo run -p nclr-core --bin nclr-lab -- \
  trace factory-success.pcapng \
  -o factory-success.ndjson
```

decoder は bulk endpoint の `usb.frame.data` だけを読み、device ごとに CBW と CSW を対応付ける。次を満たさない capture は拒否する。

- CBW は 31 byte、signature は `USBC`、CDB length は 1–16、reserved bit は 0。
- transfer length は実装上限 64 MiB 以下で、data 合計は `dCBWDataTransferLength - dCSWDataResidue` と完全一致する。
- CSW は 13 byte、signature は `USBS`、tag は CBW と一致し、status は 0–2 である。
- 新しい CBW が未完了 command を上書きしない。capture 終端に未完了 command を残さない。

SanDisk U3 trace では `FF 20`–`FF 25` の domain configuration、`FF 40`–`FF 42` の CD domain、`FF A0` / `FF A2`–`FF A7` の logical security command を D1–D4 command と分類しない。特に `FF 22` は `setDomains` であって physical erase ではなく、`FF 42` は 2048-byte 単位の ISO block write であって raw NAND page/OOB program ではない。`nclr-lab decode` はこの区別を表示し、`sandisk-cruzer` recipe validator も既知 U3 CDB の raw NAND role への割り当てを拒否する。

既定出力は CDB、方向、length、status、payload SHA-256 だけで、data payload は出力しない。byte 列が解析に不可欠な場合のみ、両方を明示する。

```sh
nclr-lab trace factory-success.pcapng \
  --include-payload \
  --confirm-sensitive-payload \
  -o sensitive.ndjson
```

normalized NDJSON は `decode`、`diff`、`infer`、read-only 限定の `replay` へ渡せる。write / unknown opcode は replay されない。

## Production profile の必須条件

実媒体で `trust = "production"` を成立させるには、従来の exact firmware / NAND、D1–D4 accounting、BBT / FTL / spare rebuild、HIL 条件に加え、次を profile validator が強制する。

1. `implementation.strategy`: `clean-room` または `runtime-artifact`。
2. `protocol_evidence_sha256`: 同じ profile 内の `protocol-trace` artifact と一致。
3. `source_reference`: user information を含まない HTTPS URL。
4. runtime artifact id: profile 内の exact controller / firmware / NAND artifact を参照。`protocol-recipe` はちょうど 1 個、`role = "runtime"` でなければならない。`strategy = "runtime-artifact"` は backend が実際に controller へ渡す `service-loader` を最低 1 個要求し、factory-tool PE / archive だけでは成立しない。固定 probe を持たない family の bootstrap は USB VID / PID / bcdDevice / manufacturer / product / serial と SCSI vendor / product / revision を全て exact に固定する。
5. geometry: channel、CE、LUN、plane、block、page、page/OOB size、address cycle、bits/cell、FBB marker、randomizer、read-retry、ECC layout。
6. metadata: BBT / FTL / spare format、atomic commit protocol、順序付けされた非重複 system block range。
7. qualification report: `qualification-report` artifact の SHA-256 と `report_sha256` が一致。

TOML だけでは capability を有効化できない。profile、recipe、trace、qualification report、必要な loader の全 byte 列が hash 一致し、controller-owned response から exact controller / firmware / NAND が再確認された場合だけ C3/C4 capability を公開する。

初回の読み取り専用 probe は trusted exact profile から必要 runtime artifact 一覧を plan に固定できるが、これは実行許可ではない。`run` の再 probe で recipe と必要な loader を含む inherited FD を size / SHA-256 / format 検証し、実 NAND ID 再確認が完了して初めて destructive capability を executable とする。

## Family ごとの次工程

### Phison

実装済み前提は、署名付き version page / NAND ID、BootROM CDB、`BtPramCd` parser、512-byte unit の header / body transfer、各 chunk の `06 B0` acknowledgement、PRAM run CDB である。recipe が entry / loader の USB reset を宣言した場合、core は最大 2 回、元の physical USB path に現れた唯一の device だけへ block/SG FD を付け替え、永続 state から同一 action を進める。exact NAND ごとに次の実測値と HIL 認定が必要である。

- service loader を source から再現するか、正規入手 byte 列を artifact として固定する。
- 全 CE / LUN / plane / block の列挙、FBB marker 保存、raw erase result、read-retry / ECC telemetry を実装する。
- 旧 RBB を消去した証跡を保持し、dual-copy BBT / FTL を inactive copy へ書き、verify 後に generation を切り替える。
- すべての power-cut point から旧または新の一方へ回復することを独立 reader で確認する。

公開 `bnReadNand` の固定 `0x400 + 0x40` layout は loader 固有であり、一般 NAND geometry として使用しない。

### Alcor

config read と flash-ID read は identity にだけ使う。`0x81 00 ff` config write を erase / rebuild と解釈しない。正規 tool capture から確定した service transition、raw NAND operation、metadata commit は `family = "alcor-ufd"` recipe として engine に渡せる。成功 / 失敗 trace の response signature と各 field を HIL で確定する必要がある。

### Silicon Motion

公開 transcript の identity CDB 以外に、D1–D4 用 service CDB の確定資料はない。正規 tool を利用環境で取得できた場合は、USB capture を上記 decoder へ通し、controller-owned response signature と bounded command grammar を `family = "silicon-motion-ufd"` recipe に固定する。VID、tool filename、二次配布 archive だけを根拠に opcode を実装しない。

### SanDisk Cruzer

`family = "sandisk-cruzer"` は通常 probe で vendor CDB を送信しない。まず profile の `controller_bootstrap` に、実対象から取得した `usb_vid = 0x0781`、exact `usb_pid`、exact `usb_bcd_device`、USB manufacturer / product / serial、SCSI INQUIRY の exact vendor / product / revision を固定する。これは plan が必要 artifact を一意に選ぶためだけの selector である。

正規 tool trace では、書き込みや mode 遷移より前に成功している device-to-host command を抽出し、犠牲媒体の chip marking と response の対応を確認する。controller / firmware を区別する stable payload window を `controller_identity_hex` と `read-controller-id` に、NAND die を区別する raw ID window を `nand_id` と `read-nand-id` に固定する。可変 serial、counter、checksum を identity payload に含めず、固定 signature と field rule で別に検査する。両 response の exact match が終わるまでは service entry を含む破壊 command を実行しない。

`82-00263-1` では `SDTNNNAHSM-004G` と `SDTNNNAHEM-004G` の報告があり、同じ `45 c7 98 b2` prefix でも 16-bit bus、page / sector、XOR 条件が異なる。したがって marking 単位の共通 geometry recipe を作らず、controller response、firmware、完全な NAND ID、bus width、randomizer / XOR、ECC、page/OOB、BBT/FTL layout の tuple ごとに recipe と profile を分ける。
