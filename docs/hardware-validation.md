# nclr 実機検証ガイド (Linux)

このガイドは、macOS では検証できない **Linux 実機パス** の確認手順です。
Linux 実機パスの確認手順として使います。
すべての実機操作は対象デバイスを慎重に確認して行ってください。

## 前提

- Linux (x86_64 または arm64)、root 権限
- `cargo build --workspace --release` 済み。`NCLR_BACKEND_DIR` に
  `nclr-lba` / `nclr-scsi` / `nclr-sd-native` / `nclr-controller` を配置
- 検証対象: scsi_debug(仮想SCSI)、USBメモリ、SDカード(ネイティブホスト)

## 1. scsi_debug による SCSI パス検証 (root)

```sh
modprobe scsi_debug dev_size_mb=64 num_tgts=1
# ブロックデバイスと sg ノードを確認
ls /sys/class/scsi_device/  # scsi_debug で 1 デバイス出現
ls /dev/sg* | tail -1        # 対応する sg ノード

# 識別 (SG_IO が通ること)
NCLR_BACKEND_DIR=target/release ./target/release/nclr info /dev/sdb
# => Transport: usb-msd (scsi_debug は USB ではありませんが、SG_IO 経路は同一)
#    Backend: scsi / Grade ceiling を確認

# SANITIZE 能力検出 (scsi_debug は RSOOC 応答次第)
NCLR_BACKEND_DIR=target/release ./target/release/nclr plan -l best /dev/sdb | jq '.expected_grade'
# scsi_debug が SANITIZE をサポートしない場合は C1 計画になる(それも正しい)

# LBA C1 レシピ全容量実行
./target/release/nclr run -l lba /dev/sdb --yes -j > report.json
jq '{result, achieved_grade, health_grade}' report.json
```

期待結果:
- `info` が INQUIRY ベースの識別と SCSI バックエンドを表示する
- `run -l lba` が C1 / H2 を達成する(SG_IO の READ/WRITE が正しく動く)。
  実機に power cycle 制御がない場合、power-cycle 検証は省略され
  residual が documented-exclusion となり exit 1 (degraded) が正しい
  (exit 0 になるのは power cycle を行える環境のみ)
- scsi_debug が SANITIZE を実装していない場合は `plan -l device` が exit 2
  (要求 C2 は計画不能) — これも正しい動作

## 2. USB フラッシュメモリ (実機)

```sh
# 事前確認: 対象を完全に特定する
lsblk -o NAME,SIZE,MODEL,SERIAL,TRAN
# 該当デバイスを1本だけ挿す(識別の曖昧さを排除)

NCLR_BACKEND_DIR=target/release ./target/release/nclr info /dev/sdX
NCLR_BACKEND_DIR=target/release ./target/release/nclr plan -l best /dev/sdX > usb.plan
jq '.expected_grade, .backend' usb.plan
# SANITIZE 対応コントローラなら C2 計画、非対応なら C1

./target/release/nclr run --plan usb.plan /dev/sdX --yes -j > usb.report
jq '{result, achieved_grade, residual, health_grade}' usb.report
```

チェック項目:
- `info` で VID/PID/serial が正しく取れるか(USB 経路の識別)
- C2 計画時: SANITIZE の IMMED 起動 → progress イベントが流れるか
  (`--events-fd 9 9>ev.ndjson`)
- `run` 後の論理領域に MBR/GPT/FAT 署名が残らないか
- 電源再投入ができない場合は `degraded` + `documented-exclusion` になる
  (それで正しい)

## 3. ネイティブ SD カード (MMC)

```sh
# /dev/mmcblk0 が対象(全体デバイスであること。mmcblk0p1 は不可)
NCLR_BACKEND_DIR=target/release ./target/release/nclr info /dev/mmcblk0
# => Transport: mmc、CID/CSD/SCR 表示

NCLR_BACKEND_DIR=target/release ./target/release/nclr plan -l best /dev/mmcblk0 | jq '.expected_grade'
# SD 標準 full-range ERASE (CMD32/33/38) が宣言されれば C2 計画

# 破壊的実行(該当カードを完全に消去します)
./target/release/nclr run -l best /dev/mmcblk0 --yes -j > sd.report
jq '{result, achieved_grade, residual}' sd.report
```

チェック項目:
- `MMC_IOC_CMD` が正しくカーネルへ通るか(CMD38 ERASE が success)
- 消去後の blank 読み出しが一様値 (0x00/0xFF) になるか
- カードがリーダー越しで `/dev/sdX` に見える場合: 標準SDバックエンドは
  選択されず lba/scsi になること(カードCID へ到達不可のため)

## 4. `nclr-controller` (ベンダーコントローラー)

```sh
# 認定プロファイルが無い限り、物理的コントローラー再初期化は計画不能
NCLR_BACKEND_DIR=target/release ./target/release/nclr plan -l controller /dev/sdX
# => trusted exact profile が一致すれば必要 artifact digest を plan へ固定。
#    profile が無ければ exit 2。破壊実行は run 時の全 artifact 検証後だけ許可。
```
公開一次資料と実装済み範囲は
[`controller-vendor-support.md`](controller-vendor-support.md) を参照してください。
実ベンダーの C3 / C4 認定には:
1. 対象コントローラー (Phison/SMI/Alcor 等) のサービスモード資料
2. 正規 tool の pcapng を `nclr-lab trace` で USB BOT NDJSON へ変換し、
   成功 / 失敗 / 設定差を比較
3. service loader / tool / trace / report を `nclr-lab artifact` で
   exact SHA-256 と hardware tuple に固定
4. `nclr-lab profile --new` の雛形へ geometry、FBB、ECC、metadata commit
   layout と clean-room/runtime provenance を記録し、`nclr-lab recipe` で
   exact runtime recipe の digest、command、response、layout を検査
5. HIL fixture (犠牲媒体) での電源断・USB reset 復旧試験
6. `tests/e2e.rs` の sim 認定 fixture に相当する独立物理確認
7. レビュー済み profile を package-managed profile directory へ配置し、
   package 側で `trust = production` と digest を固定

`NCLR_PROFILE_DIR` 内の user profile が `trust = production` を自己申告しても、
実媒体の破壊的 controller operation には使用されません。
取得物を再配布しない運用の詳細は
[`controller-artifact-workflow.md`](controller-artifact-workflow.md) を参照してください。

## 5. 検証シート

| 項目 | 期待 | 実測 | 備考 |
|---|---|---|---|
| info: transport/識別 | SCSI/MMC 情報 | | |
| plan: expected_grade | C1/C2 (能力次第) | | |
| run: exit code | 0/1 (degraded可) | | |
| run: achieved_grade | 計画一致 | | |
| run: residual | none-known 等 | | |
| run: health_grade | H2 (正常時) | | |
| 署名なし確認 | MBR/GPT/FAT なし | | |
| events FD | NDJSON | | |
| evidence-dir | blocks.ndjson + digest | | |

## 注意

- 実機の電源再投入は `--power-cycle CMD`(認定外部電源制御)または
  USB ハブの物理スイッチで行います。無い場合は degraded になるのが正しい
- `--scratch-range` による check は範囲限定で復元されるため比較的安全ですが、
  マウント中デバイスでは拒否されます
- 検証には必ず犠牲にできる媒体だけを使用してください
