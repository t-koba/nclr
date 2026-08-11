# Controller protocol recipe

## 目的

`protocol-recipe` は、Phison、Alcor、Silicon Motion、SanDisk Cruzer proprietary controller の非公開 service protocol を実行 code から分離する、署名付き・完全一致の command 契約である。nclr は未知の opcode、offset、endianness、NAND geometry を推測しない。正規 tool の capture または clean-room 実装から確定した値だけを JSON / TOML artifact に記録し、production profile が size と SHA-256 を固定する。

recipe は汎用 script ではない。loop、分岐、任意 path、shell command は表現できず、次の固定 command と bounded field binding だけを許可する。

## Hardware binding

top-level の `controller_id`、`firmware`、`nand_id` は production profile の exact `min = max` と byte 単位で一致しなければならない。`family` は次のいずれか、`transport` は `scsi-sg` に限定される。

- `phison-ps2251`
- `alcor-au698x`
- `smi-sm32x`
- `sandisk-cruzer`

公開済みの固定 read-only identity CDB がない family、後期世代、または OEM VID の製品では、profile の `controller_bootstrap` に family、USB VID、PID、bcdDevice と SCSI INQUIRY vendor、product、revision の完全一致 tuple を持てる。この tuple は必要 recipe artifact を選ぶだけで、破壊処理を許可しない。runtime recipe は stable な controller-owned response payload を `controller_identity_hex` に固定し、後述の `read-controller-id` で byte 単位に再確認する。同じ bootstrap tuple に複数の production profile が一致した場合は曖昧性 error とし、NAND を推測しない。SanDisk Cruzer はこの経路を必須とする。Phison、Alcor、SMI も exact profile が明示した場合に限ってこの経路を使え、組み込み probe 失敗から暗黙に family を推測しない。

recipe artifact 自体も profile の `kind = "protocol-recipe"`、`role = "runtime"`、`format = "json"` または `toml`、exact size / SHA-256 で認証される。

## 必須 command

| command | 役割 | 必須の追加契約 |
|---|---|---|
| `read-controller-id` | bootstrap 選択後の controller / firmware identity 再確認 | `controller_bootstrap` を持つ profile で必須。device-to-host、非空 response signature、exact `controller_identity_hex` と同じ長さの payload window |
| `read-nand-id` | 実行直前の NAND identity 再確認 | device-to-host、exact `nand_id` と同じ長さの payload window |
| `read-bbt` | 旧 BBT 取得 | device-to-host、非空 response signature |
| `read-page` | page + OOB 取得 | device-to-host、ECC / retry / latency field、payload window |
| `erase-block` | 物理 block erase | coordinate field binding |
| `read-status` | destructive command status | `busy`、`failed`、`service_mode`、非空 signature |
| `program-page` | qualification page program | host-to-device、`caller` payload |
| `prepare-bbt` | inactive BBT staging | host-to-device、固定長 `bbt` payload |
| `prepare-ftl` | inactive FTL staging | host-to-device、固定長 `ftl` payload |
| `set-capacity` | logical capacity staging | host-to-device、固定長 `capacity` payload |
| `activate-metadata` | generation / commit marker 切替 | generation field を利用可能 |
| `read-commit-state` | atomic commit 確認 | `busy`、`failed`、`generation`、`committed`、非空 signature |
| `enter-service-mode` | service mode 遷移 | 固定 CDB または固定 artifact payload |
| `exit-service-mode` | normal mode 復帰 | 固定 CDB または固定 artifact payload |
| `reset-controller` | profile recovery | 固定 CDB または固定 artifact payload |

各 command は USB BOT の上限に合わせた 6–16 byte の固定 `cdb_hex`、100–3,600,000 ms の timeout、16 MiB 以下の固定 transfer length を持つ。byte 0 の opcode は field binding で変更できない。field binding は重複不可で、`channel`、`chip`、`lun`、`plane`、`block`、`page`、`flat-block`、`payload-bytes`、`generation`、`user-blocks`、`spare-blocks` の整数だけを明示した offset / width / endian へ書き込める。

host-to-device command は payload source を必須とし、実際の payload 長が固定 transfer length と完全一致しなければ送信しない。device-to-host command は SG residual から実 transfer 長を取得し、declared min/max、signature、field boundary を検証する。`read-page`、`program-page`、`erase-block` は `flat-block` だけ、または `channel` / `chip` / `lun` / `block` の完全な組を必須とし、両方式の混在を拒否する。page command は `page`、metadata activation は `generation` の binding が必須である。

`read-page` は必ず page data + OOB を返す。`program-page` は raw OOB を controller が受け取る方式と、ECC / OOB を controller が生成する方式の双方に対応するため、transfer length を `page_bytes + oob_bytes` または `page_bytes` のどちらかへ exact に固定する。qualification は後者でも別の raw read により FBB marker が消えていないことを確認する。

## Signed response と payload window

`response.prefix_hex` は controller-owned response の固定 signature である。`fields` は offset、1/2/4/8 byte width、endian、任意 mask、任意 exact value を宣言する。同名 field、overlap、範囲外 field、field width に収まらない mask / exact value、mask 外 bit を持つ exact value は拒否する。

page read のように status header と NAND data が同じ response に入る protocol では、`payload_offset` と `payload_bytes` で logical payload window を指定する。`read-page.payload_bytes` は profile の `page_bytes + oob_bytes` と完全一致しなければならない。FBB marker と qualification compare は envelope を除いたこの window だけを使う。

## BBT と FTL

`bbt` は旧 BBT response の count、entry stride、block address、state byte を定義する。block address は global `flat` integer、独立した channel / chip / LUN / block field、または channel / chip / LUN / plane / block-in-plane field で表現できる。FBB、RBB、system の state value は非空・相互排他で、table は全 physical block を表現できなければならない。未知 state、duplicate block、範囲外 coordinate は hard error である。新 BBT の entry address も同じ方式を選択できる。

`bbt_output` は新 BBT の固定長 staging image を定義する。header、generation、count、entry、checksum、commit byte の領域は境界検査され、管理 field と entry field の overlap は拒否される。BBT、FTL、capacity の未使用 byte は各 layout の必須 `fill_byte` で埋め、entry 数にかかわらず command の固定 transfer length と常に一致させる。controller 固有の `00` / `ff` padding を実装側で推測しない。

`ftl_output` は固定長 FTL staging image を定義し、generation、user block 数、spare block 数、新 BBT の SHA-256、checksum、commit byte を含む。`capacity_output` は header、値 offset / width / endian、`user-blocks` または `user-bytes` の意味を宣言し、hard-coded little-endian 変換を使わない。

BBT / FTL の `prepare_value` と `commit_value` は異なる必要がある。checksum は `crc`、`sum`、`xor8` を選べる。CRC は 8 / 16 / 32 / 64 bit の polynomial、initial、xor-out、reflected を exact に宣言し、sum は width と 2 の補数化を宣言する。offset / endian / coverage start / length を固定し、commit byte を coverage に含めてはならない。これにより特定 vendor の CRC32 を仮定せず、inactive copy を `prepare_value` で検証可能に書き、最後の `activate-metadata` だけで generation / commit marker を切り替えられる。

## 物理処理 sequence

real C3/C4 action は次の順序で動く。

1. signed commit state と inventory を取得する。
2. 旧 BBT を読み、FBB / historical RBB / system block を block map へ固定する。
3. service mode へ入り、全 CE / LUN / block の marker page + OOB を列挙する。
4. 旧 RBB と data block を個別 erase し、status と erased page を確認する。
5. 各候補 block を pattern ごとに erase、複数 page program/read/compare し、ECC corrected bits、read retry、latency threshold で weak block を隔離する。
6. qualified block を最終 erase し、FBB、historical RBB、new quarantine、system reservation から user/spare pool を決める。
7. 全 CE / LUN / block / page を data + OOB で再読する。FBB、preserve、unknown を含む全 address の読取成否を記録し、erase 対象は全 byte が erased byte であることを確認する。
8. 物理 blank 確認後に inactive BBT、inactive FTL、capacity を staging し、generation を atomic activate する。
9. BBT の block/state 全件と signed commit generation を再読して一致を確認する。
10. service mode を終了し、power cycle、再列挙、postcheck を行う。

旧 RBB は erase を試行しても data pool に戻さない。FBB marker block と `policy = "preserve"` の system block は erase / program target にしない。erase / program failure と ECC margin 不足は block を quarantine し、暗黙の再利用を行わない。

`nclr salvage` は同じ列挙と `read-page` を read-only recipe として利用し、erase / program / metadata activation を一切送らない。raw image は flat block、page、data + OOB の固定順で作る。page map は全 page の offset、disposition、ECC / retry / latency、digest を保持し、読取不能 page は固定長の zero hole と `read-error` を必ず対にする。出力 path は backend へ渡さず、core が新規作成した継承 FD のみを渡す。

## 電源断と再開

controller state は journal と別の 128 MiB 超の sparse 専用 file に保持し、2 個の 64 MiB data slot と独立 descriptor を使う。更新は inactive slot data の write + `fsync`、その SHA-256 / sequence descriptor の write + `fsync` の順である。最新 descriptor または payload が破損していれば、直前の完全な slot へ戻る。初回 allocation 中断による全 zero descriptor だけは未初期化として再開できるが、非 zero descriptor が 1 個も検証できない file は破損として拒否する。

物理 erase / program の直前には `in_flight` を永続化する。erase 再開時は `read-status` と erased-page read を行い、完了が証明できない場合だけ bounded retry を使う。metadata activation の response が失われた場合は、同じ generation の signed `read-commit-state` を先に確認し、commit 済みなら activate command を再送しない。

entry、任意 Phison RAM loader、exit が USB reset を起こすかは recipe policy で個別に宣言する。core は元の physical USB path に現れる whole block device がちょうど 1 個の場合だけ block/SG FD を再度開く。artifact と controller-state FD は交換しない。entry + loader は最大 2 回、exit は最大 1 回に制限し、各境界を journal へ `fsync` する。

## 検査

profile に固定された recipe を実行せずに検査する。

```sh
nclr-lab recipe \
  --profile exact-production.toml \
  --file exact-recipe.json
```

この command は profile、artifact size / SHA-256 / format、exact hardware tuple、全 command contract、response signature / field、NAND geometry、FBB marker、BBT / FTL / capacity layout、qualification policy、再列挙 policy を検査する。成功は protocol の HIL 認定を意味しない。production には profile が要求する独立 qualification report と power-cut case が別途必要である。
