# CapLock

**A lockfile for the MCP servers your agents use.** CapLock pins what you approved — the config
entry, the exact package (version + integrity), the tool surface, and each tool's capability — in
one committed `mcp-lock.json`, reports every change against it, and fails CI on high-severity
changes or anything it cannot verify. Offline by default; tool descriptions never leave your machine.

**What it catches (CapLock Bench v0, synthetic, 90 cases):**
holdout detection 38/41 (92.7%), false positives on benign controls
0/7 (0.0%), exit-code agreement 45/48
(dev: 36/36 (100.0%)). The holdout misses are paraphrased prompt injections, which
CapLock reports only as a medium `description_changed`. Method and limits: `bench/RESULTS.md`;
the 48 holdout cases are withheld from this repository (`bench/cases/HOLDOUT.md`).

Drift survey (2026-10-31, registry metadata only): of the 30 most-downloaded npm-backed entries in the official MCP registry, 0 publish a machine-readable tool list without running the server, so surface drift could not be measured; their packages shipped 1151 versions in the last 90 days (26/30 packages), and 0/19646 npm/PyPI package entries in the registry carry a content hash.

**Try it in 30 seconds** (Python 3.12; the demo itself needs no network and runs only a local fixture server):

```bash
git clone https://github.com/NagaYu/caplock caplock && cd caplock
python3.12 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python scripts/demo.py --brief
```

**Limits.** CapLock pins the declared tool surface and the package identity. It does not attest to the
runtime behavior or safety of any server: a matching lockfile means "the same thing you approved",
not "safe". It does not see mid-session `list_changed` swaps, and it cannot pin remote (http) servers.

---

## CapLock — 詳細ドキュメント（日本語）

CapLock は、AI エージェントが使う MCP サーバーについて「承認した中身」を
リポジトリにコミットする 1 つの lockfile（`mcp-lock.json`）に固定し、
その後の変更を検知する開発者向け CLI です（Phase 1: Bind / Phase 2: Review / Phase 3: Evidence & Bench）。

lockfile は次の 4 つを 1 本の鎖として結び付けます。

```
設定エントリ ─→ 解決済みパッケージ（版数 + integrity）─→ tool サーフェス ─→ tool ごとの capability
```

## CapLock が保証しないこと（最初に読んでください）

- CapLock が固定するのは **宣言されたサーフェス（tool 定義）とパッケージの同一性** です。
  **サーバーの振る舞いや安全性は保証しません。** lockfile と一致していても、
  そのサーバーが安全だという意味にはなりません。承認したときと同じものだ、という意味です。
- 分類（capability）は、サーバー自身が申告した annotations・名前・schema・説明文に対する
  決定的なルールです。サーバーは嘘をつけます。分類は「承認の単位」であって、実際の
  挙動を観測したものではありません。
- integrity は、レジストリのメタデータがその版数について示すハッシュです。
  列挙のために起動したプロセスが、そのアーカイブから作られたものであることは
  Phase 1 では証明しません（下の「Phase 1 の限界」を参照）。

## 動作要件・インストール

- Python 3.12 以上。実行時の依存はゼロ（標準ライブラリのみ）。
- MCP SDK にも依存しません。列挙に必要なのは `server/discover` / `initialize` /
  `tools/list` などの最小セットなので、JSON-RPC クライアントは自前で実装しています。

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[test]'
```

インストールせずに `PYTHONPATH=src python -m caplock ...` でも動きます。

## クイックスタート（デモ）

```bash
.venv/bin/python scripts/demo.py           # lock → 変異 → verify/diff で検知、までを表示
.venv/bin/python scripts/demo.py --brief   # 結果表だけ
```

デモは `examples/demo-workspace` の一時コピーに対して動き、起動するのはローカルの
fixture サーバー（`fixtures/servers/notes_server.py`）だけです。レジストリ情報は
`fixtures/registry/` の記録を使うので、ネットワークには一切出ません。

## コマンド

```
caplock lock   [options] [--yes]   mcp-lock.json を生成・更新
caplock verify [options] [--format F] [--output P] [--report F=P] [--fail-on T]
                                   現在の状態を再構成して lockfile と突き合わせる
caplock diff   [options] [--format F] [--output P] [--report F=P]
                                   tool 単位・フィールド単位の差分を before/after 付きで表示
caplock evidence [options] [--out DIR] [--zip] [--fail-on T] [--sarif F --markdown F]
                                   lockfile・verify 結果・manifest を証跡パックに束ねる（Phase 3）
caplock evidence --verify PACK     パックを manifest と照合する（改竄検出。出所証明ではない）
```

| 出力オプション（verify / diff） | 意味 |
|---|---|
| `--format text\|json\|sarif\|markdown` | 出力形式。既定は `text`。`--json` は `--format json` と同じ |
| `--output PATH` | `--format` の出力を標準出力ではなくファイルに書く |
| `--report FORMAT=PATH` | 同じ 1 回の実行から、別の形式もファイルに書く（複数指定可）。例: `--report sarif=caplock.sarif --report markdown=caplock.md` |
| `--fail-on info\|medium\|high\|critical\|never` | verify のみ。終了コード 1 を返す重大度の閾値（既定 `high`） |

| オプション | 意味 |
|---|---|
| `-w, --workspace DIR` | ワークスペース（既定 `.`）。`.vscode/mcp.json` と `.mcp.json` を探す |
| `--lockfile PATH` | lockfile のパス（既定 `<workspace>/mcp-lock.json`） |
| `--config PATH` | 追加の portable 形式設定（`~/.copilot/mcp-config.json`、Claude Desktop の設定など）。複数指定可 |
| `--registry DIR` | 記録済みレジストリメタデータのディレクトリ。複数指定可、先に指定したものが優先 |
| `--online` | npm / PyPI の公開メタデータを取得する。**送るのはパッケージ名と版数だけ**で、tool の定義は送らない |
| `--launch NAME=COMMAND` | サーバー NAME を列挙するために、この明示したローカルコマンドを起動する |
| `--allow-launch NAME` | サーバー NAME の設定上のコマンドを起動して列挙することを許可する（引数に秘密や未解決変数があると拒否） |
| `--surface NAME=FILE` | 記録済みの `tools/list` 応答を取り込む（http サーバーはこの方法のみ） |
| `--pass-env KEY` | 起動するサーバーへ渡す環境変数（値はどこにも記録しない） |
| `--timeout SEC` | 1 リクエストあたりのタイムアウト（既定 10 秒） |

明示的に許可されないかぎり、CapLock はサーバーを起動しません。起動するときは、
環境変数を最小の許可リスト（`PATH`, `HOME`, `LANG`, `TMPDIR` など）と `--pass-env`
で指定したものだけに絞り、タイムアウトを付け、stderr は捨てます（秘密が出力に
混ざらないようにするため）。

`caplock lock` は、既存の lockfile との差分があると変更サマリを表示し、確認を求めてから
上書きします。`--yes` を付けると確認を省略します（対話用途を想定しており、CI で
自動承認するためのものではありません）。端末でなく `--yes` もない場合は、何も
書かずに中止します（終了コード 3）。

## 終了コード

| コード | 意味 |
|---|---|
| 0 | 差分なし、または `--fail-on` の閾値未満の finding のみ（既定では medium / info のみ） |
| 1 | `--fail-on` の閾値以上の finding が 1 つ以上ある（既定 `high`: high または critical） |
| 2 | **検証不能**な項目がある（バージョン未固定、integrity 未記録、http リモート、列挙失敗、lockfile がない・壊れている、など） |
| 3 | 使い方の誤り、またはユーザーによる中止 |

**優先順位（正式仕様）: 2 > 1 > 0。** 検証が不完全なときは、ほかに何が見つかっていても
「完了した」とは報告しません。**未検証のまま 0 を返すことはありません。**
3 は検証の結果ではなく、CLI の使い方の誤りやユーザーによる中止を表します（argparse の既定の 2 を上書きしています）。
`caplock lock` も、書き込んだ lockfile に検証不能な項目が含まれる場合は 2 を返します。

### `--fail-on` と終了コードの対応

`--fail-on` が変えるのは「1 を返す閾値」だけです。検証不能（2）の意味と優先順位は変わらず、
`--fail-on never` でも検証不能なら 2 を返します。

| `--fail-on` | 1 になる finding | 検証不能があるとき |
|---|---|---|
| `info` | info / medium / high / critical | 2 |
| `medium` | medium / high / critical | 2 |
| `high`（既定・Phase 1 と同じ） | high / critical | 2 |
| `critical` | critical | 2 |
| `never` | なし（常に 0） | **2** |

## 何を「検証不能」とするか

| finding | 原因 |
|---|---|
| `floating_version` | バージョン指定なし、`@latest`、範囲指定（`^` `~` `*` `>=` …）、dist-tag、docker のタグなし / `:latest` |
| `package_unresolvable` | npx / uvx / docker 以外のコマンド、git・URL・パス指定、`uvx --with` など |
| `integrity_unrecorded` | オフラインでレジストリ情報がない、またはその版数が公開されていない |
| `remote_entity_unverifiable` | http サーバー：URL の向こうのコードは固定も観測もできない |
| `enumeration_failed` | 起動失敗、タイムアウト、プロトコル版数の不一致、tool 名の重複など |
| `surface_not_enumerated` | 列挙の手段（`--launch` / `--allow-launch` / `--surface`）が指定されていない |
| `lock_incomplete` | lockfile 側に integrity やサーフェスが記録されていない |
| `lockfile_missing` / `lockfile_invalid` | lockfile がない、スキーマ違反、記録した hash と定義が一致しない |
| `config_error` / `no_config` | 設定ファイルが壊れている、または見つからない |

## 正規化規則（tool 定義のハッシュ）

実装は `src/caplock/canonical.py`、固定するテストは `tests/test_canonical.py` です。

1. 対象のフィールドは `name`, `title`, `description`, `inputSchema`, `outputSchema`,
   `annotations` だけです（`_meta` や `icons` などは含めません）。
2. オブジェクトのキーを再帰的にソートします（コードポイント順）。キーは NFC にしますが、
   前後の空白は除去しません。
3. 文字列の値はすべて Unicode NFC にしたうえで、前後の空白（`str.strip()`）を除去します。
   内部の空白は保持します。
4. 数値の表現をそろえます。整数値の float（`1.0`, `1e1`, `-0.0`）は整数にし、それ以外は
   最短の往復表現にします。NaN / Infinity は拒否します。真偽値は数値と区別します。
5. 配列の順序は保持します（`enum` のように順序に意味があることがあるため）。
6. 区切り `,` / `:` のコンパクトな JSON（UTF-8、ASCII エスケープなし）にして SHA-256 を取り、
   `sha256:<hex>` と表記します。
7. サーバー単位の surface hash は、`{tool 名: tool hash}` の対応表を同じ規則でハッシュしたものです。

**不可視文字は正規化で消しません。** ゼロ幅文字、BOM、bidi 制御文字、タグ文字、
異体字セレクタなどは hash を変え、`invisible_chars` finding として別途報告します。
lockfile では `\uXXXX` 形式でエスケープして書くので、コードレビューで見えます。

この規則により、キー順・整形・Unicode の正規化形の揺れ・数値の表記違いだけの変更は、
差分として数えられません（シナリオ H）。

## lockfile（`mcp-lock.json`）

```jsonc
{
  "lockfileVersion": 1,
  "notice": "CapLock pins the declared tool surface and the package identity. It does not attest to ...",
  "approval": { "generatedAt": "2026-10-31T00:00:00Z", "caplockVersion": "0.1.0" },
  "servers": {
    "notes": {
      "config":     { "transport": "stdio", "command": "npx", "args": [...], "envKeys": ["NOTES_TOKEN"], ... },
      "configHash": "sha256:…",
      "sources":    [{ "path": ".vscode/mcp.json", "format": "vscode" }],
      "package":    { "ecosystem": "npm", "name": "@caplock-demo/notes-mcp", "version": "1.0.0",
                      "integrity": "sha512-…", "resolution": "fixture-registry", "status": "resolved", "pinned": true },
      "surface":    { "status": "enumerated", "method": "launch-override", "protocolVersion": "2026-07-28",
                      "hash": "sha256:…", "toolCount": 3, "resourcesHash": "…", "promptsHash": "…" },
      "tools": {
        "read_note": {
          "definition": { /* 正規化済みの tool 定義そのもの */ },
          "hash": "sha256:…",
          "capability": { "capabilities": ["read"],
                          "evidence": [{ "capability": "read", "source": "annotations.readOnlyHint", "detail": "true" }] },
          "flags": [ /* lock 時点の不可視文字・命令的文言（あれば） */ ]
        }
      }
    }
  }
}
```

- 出力は決定的です（キーをソートし、インデント 2、末尾に改行）。中身が変わらなければ
  `caplock lock` はファイルを書き換えません。
- 読み込むときはスキーマを検証し、各 tool の hash と surface hash を記録された定義から
  再計算して照合します。手で書き換えると `lockfile_invalid`（終了コード 2）になります。
- PyPI は、その版数の配布ファイルごとの sha256 を `integritySet`
  （`[{file, sha256}]`、file 名でソート）として記録し、比較用の `integrity` は
  その集合の正規化 JSON の sha256（`sha256:…`）とします。レビュアーはファイル単位で読め、
  照合は一括でできます。不一致のときは、変わったファイルだけを finding に示します。
  npm の integrity はレジストリの SRI（`sha512-…`）、docker の integrity はイメージのダイジェストです。

## 秘密の扱い

値は扱わず、キー名だけを扱います。

- `env` と `headers` は**キー名だけ**を記録します。
- URL のユーザー情報（`user:pass@`）とフラグメントは捨て、クエリは値を `<redacted>` にします。
  トークンのように見えるパスセグメントも伏せます。
- 引数のうち、`--token` / `--api-key` などの値、docker の `-e KEY=value` の値、
  既知のトークン形式（`ghp_`, `sk-`, `xoxb-`, `AKIA…`, JWT）、高エントロピーの文字列は伏せます。
- VS Code の `${input:...}` / `${env:...}` は解決しません。`${input:...}` を含むエントリには
  「要対話入力」の印を付けます。

この性質は、lockfile・テキスト出力・JSON 出力について、テスト
（`test_secret_values_never_leave_the_config`）で確かめています。

## capability 分類（決定的ルール）

実装は `src/caplock/capability.py` です。発火したルールはすべて `evidence` として
lockfile に書きます。

| 入力 | ルール |
|---|---|
| annotations（**明示されたものだけ**。MCP の既定値は仮定しない） | `readOnlyHint=true`→read、`false`→write、`destructiveHint=true`（readOnly でない場合）→destructive、`openWorldHint=true`→network |
| tool 名のトークン | 固定の動詞表（get/list/read…、create/write/update/send…、delete/remove/drop…、exec/shell/command…、fetch/http/url/email…） |
| inputSchema | 宛先らしいプロパティ（`url`, `endpoint`, `webhook`, `email`, `cc`, `bcc`, `forward`…）や `format: uri/email` → network、`command`/`script` → exec。`default`/`enum`/`const`/説明の中の URL ホストを `networkHosts` に記録 |
| 説明文 | 先頭の動詞、固定の言い回し（「shell command」「permanently」「read-only」…）、URL のホスト |

ルールは capability を追加するだけで、推測による格上げも格下げもしません。どのルールにも
当てはまらなければ `unknown` のままにします。矛盾する根拠（readOnlyHint=true なのに
削除の動詞がある、など）は `conflicts` に残し、どちらかに解決はしません。

## 意味差分の重大度（初版）

| 重大度 | finding |
|---|---|
| critical | `capability_expanded`（write / destructive / exec / network の追加）、`annotation_readonly_revoked`（readOnlyHint true→false または消失）、`annotation_destructive_added`、`integrity_mismatch`（同じ版数で integrity が違う。tool 定義が不変でも検知する）、`package_changed`、`remote_host_changed`（URL のホスト）、`network_host_added`（tool の通信先ホスト） |
| high | `tool_added`、`server_added`、`instruction_injection`（既知の単純なパターンのみ）、`invisible_chars`、`required_param_added`（新しい必須パラメータ、または任意→必須）、`capability_unknown`、`config_changed`（コマンドや transport の変更） |
| medium | `optional_param_added`、`param_removed`、`schema_changed`、`description_changed`、`title_changed`、`output_schema_changed`、`annotation_changed`、`tool_removed`、`server_removed`、`config_changed`（引数・env キー）、`auxiliary_changed`（resources / prompts / instructions）、`config_drift` |
| info | `version_changed`（サーフェス不変なら明記）、`capability_reduced`、`network_host_removed`、`interactive_input_required` |
| （差分なし） | キー順・整形・正規化形の違いだけの変更 |

`instruction_injection` が見るのは次のパターンだけです（過検知を避けるため）。
隠し指示のタグ（`<IMPORTANT>` など）、「ignore previous instructions」、
「do not tell the user」、機密ファイルへの言及（`~/.ssh`, `id_rsa`, `mcp.json` など）。
新しく現れたものだけを報告します。

## MCP プロトコル対応

現行の MCP 仕様（2026-07-28 版）はステートレスです。`initialize` ハンドシェイクがなくなり、
すべてのリクエストに `_meta`（protocolVersion / clientCapabilities）を付けます。
CapLock のクライアントは両方の世代に対応していて、仕様の stdio 後方互換手順に従います。

1. `server/discover` で問い合わせる（`_meta.io.modelcontextprotocol/protocolVersion = "2026-07-28"`）。
2. `DiscoverResult` が返れば modern として扱い、以後の `tools/list` などにも `_meta` を付けます。
   `UnsupportedProtocolVersionError`（-32022）が返った場合は、共通の版数を選び直すか、
   失敗にします。**legacy には落としません。**
3. それ以外のエラー、または一定時間（既定 3 秒）応答がなければ legacy として扱い、
   `initialize`（2025-11-25 / 2025-06-18 / 2025-03-26 / 2024-11-05）→
   `notifications/initialized` へ切り替えます。

`tools/list` は `nextCursor` に従ってページングします（ページ数の上限と、同じカーソルが
繰り返される場合の検出あり）。`resources/list` と `prompts/list` は、サーバーが
capability を宣言している場合だけ補助的に記録し、失敗しても致命的にはしません。

## CI での運用（Phase 2）

### GitHub Action

リポジトリ直下の `action.yml` は composite action です。Python 3.12 を用意して
`pip install` し、`caplock verify` を 1 回実行して SARIF と Markdown を同時に書き出します。
そのあと SARIF を code scanning に送り、PR コメントを投稿または更新し、最後に verify の
終了コードでステップを失敗させます（2 の場合は「検証不能（This is not a pass）」と表示します）。

```yaml
permissions:
  contents: read
  security-events: write   # upload-sarif
  pull-requests: write     # comment-pr
steps:
  - uses: actions/checkout@<sha>
  - uses: NagaYu/caplock@<sha>
    with:
      fail-on: high
      extra-args: >-
        --registry .caplock/registry
        --surface docs=.caplock/surfaces/docs.json
```

| 入力 | 既定 | 意味 |
|---|---|---|
| `workspace` | `.` | ワークスペース |
| `lockfile` | `mcp-lock.json` | lockfile（workspace からの相対、または絶対パス） |
| `fail-on` | `high` | 上の対応表のとおり |
| `online` | `false` | `true` で `--online`（下記） |
| `upload-sarif` | `true` | `github/codeql-action/upload-sarif` で SARIF を送る（category `caplock`） |
| `comment-pr` | `true` | `pull_request` イベントのとき、`<!-- caplock -->` マーカー付きのコメントを 1 件だけ投稿または更新する |
| `extra-args` | `""` | `caplock verify` への追加引数（`--registry` / `--surface` / `--launch` など）。シェル風の引用で分割し、eval はしない |

`extra-args` は Phase 2 で追加した入力です。CI でサーフェスを得るには `--surface` か
`--launch` が必要で、それがないとすべてのサーバーが `surface_not_enumerated`（2）になるためです。
Action で参照する外部 action は、すべてコミット SHA で固定しています。

PR コメントは `scripts/pr_comment.py`（標準ライブラリと gh CLI のみ）が担当します。
既存のコメントのうち、本文の先頭が `<!-- caplock -->` のものを更新し、なければ新規に投稿します。
レポート中のツール由来の文字列は HTML エスケープしているので、偽のマーカーや
マークアップ、`@org/team` のようなメンションは注入できません。

### レジストリ解決の推奨（既定はオフライン）

- **既定はオフライン**です。レジストリのメタデータ（`npm/`, `pypi/`, `docker/` の記録）を
  リポジトリにコミットし、`extra-args: --registry <dir>` で渡してください。CI の結果は、
  コミットされた記録に対して決定的になります。
- `online: true`（`--online`）は、明示的に有効にした場合だけ使います。npm / PyPI に送るのは
  パッケージ名と版数だけです。認証情報やヘッダの値は、ログにも lockfile にも出しません
  （私設レジストリの認証には Phase 2 では対応していません）。
- docker のダイジェスト解決は、Phase 2 でも記録 fixture のみです（実レジストリには問い合わせません）。
  設定で `@sha256:` に固定するか、`docker/<image>.json` の記録をコミットしてください。

### SARIF の見方

| SARIF | CapLock |
|---|---|
| `ruleId` | finding の code（例 `integrity_mismatch`）。全 43 の rule を、name / shortDescription / fullDescription 付きで常に出力する |
| `level` | critical / high → `error`、medium → `warning`、info → `note`。**検証不能は重大度によらず `error`** |
| `properties.unverifiable` | 検証不能なら `true`（`tags` にも `unverifiable`）。code scanning のフィルタで握りつぶされないための印 |
| `properties.needsReview` | `version_changed` と medium の finding は `true`（`tags` に `needs-review`）。合否とは別枠 |
| `locations` | サーバーの出所の設定ファイル（リポジトリからの相対パス）。分からなければ lockfile。行番号（region）はなし |
| `partialFingerprints["caplockFinding/v1"]` | `(server, tool, code, field)` の正規化 JSON の sha256。実行をまたいで同じ finding を同じ alert として扱う |
| `runs[0].properties` | `verdict`（PASS / FAIL / UNVERIFIABLE）、`exitCode`、`failOn`、限界の注記 |

出力にはタイムスタンプがなく、並び順は重大度 → サーバー → tool → code で固定です。

### PR 用 Markdown

`caplock verify --format markdown` は、PR にそのまま貼れるサマリを出します。内容は、
判定行（PASS / FAIL / UNVERIFIABLE と根拠）、重大度別の件数と findings 表、
「Needs review」区分（`version_changed` と medium。**合否とは別枠で常に表示**します。
サーフェスが変わらなくても、版数を上げて integrity を固定し直すには人間の承認が要る、
という運用を見えるようにするため）、そして lockfile の更新手順（`caplock lock` → 差分を
レビュー → コミット）です。テキスト形式と JSON 形式の出力は Phase 1 から変えていません。

## 証跡パック（Phase 3）

`caplock evidence` は、現在のワークスペースについて次のものを 1 つのディレクトリ
（`--zip` なら決定的な zip 1 ファイル）に束ねます。

| ファイル | 中身 |
|---|---|
| `mcp-lock.json` | lockfile のバイト単位の写し |
| `verify.sarif` / `verify.md` | verify 結果（SARIF と Markdown）。既定はその場で verify を 1 回実行して書く。`--sarif F --markdown F` を渡すと、CI が出したファイルを**そのまま**同梱する |
| `approval.json` | lockfile の `approval`（生成日時と CapLock 版数）と lockfile の sha256。誰が承認したかは記録しない（レビューシステム側の記録） |
| `rule-catalog.json` | finding code / SARIF ruleId の意味を固定した、版数付きのルールカタログ（現在 `1.0.0`、43 ルール） |
| `EVIDENCE.md` | 人が読むための要約と限界 |
| `manifest.json` | 上の全ファイルの sha256 とサイズ、生成日時、CapLock 版数、ルールカタログの版数とダイジェスト、verify の判定、設定ファイルの一覧（**パスと形式だけ**。設定の中身・env やヘッダの値は含めない） |

- 終了コードは、同梱した verify 結果の終了コード（0 / 1 / 2）です。lockfile がない・壊れている
  場合は何も書かずに 2 を返します。
- `caplock evidence --verify PACK` は、manifest と実ファイルの sha256 を照合します。
  0 = 一致、1 = 改竄を検出（変更・欠落・manifest にないファイル・危険なパス）、
  2 = manifest がない・読めない（照合できない。成功ではありません）。
- **これは「パック生成後の改竄検出」であって、出所の証明ではありません。** パックには署名が
  ないので、ファイルと manifest.json を一緒に書き換えれば検出できません（テストでこの限界も
  固定しています）。生成時に表示される manifest のダイジェストを、PR やチケットなど信頼できる
  場所に別途記録してください。
- ルールカタログの版数は `src/caplock/sarif.py` の `RULE_CATALOG_VERSION` です。カタログの
  ダイジェストはテストで固定しているので、ルールを変えると版数を上げない限りテストが落ちます。
  SARIF の `tool.driver.properties` にも版数とダイジェストを出します。
- **位置付け:** Agent 365 のような審査で求められる「事前承認の証跡」を想定した CapLock 独自の
  形式です。Microsoft の公式な認定フォーマットではなく、公式の要件と照合したものでもありません。
- `SOURCE_DATE_EPOCH` を設定すると、生成日時をその値に固定します（再現可能なパック）。

## CapLock Bench v0（Phase 3）

`bench/` は、合成の変異コーパス（90 ケース、dev 42 / holdout 48）と採点ハーネスです。
シナリオ A〜I と PyPI 版 F を種に、命令文の混入・schema の拡張・annotations の反転・
tool の追加/削除・integrity の差し替え（npm / PyPI / docker）・浮動指定・良性コントロールの
各オペレータでケースを作り、`caplock verify` の結果を正解ラベルと突き合わせます。
holdout のケースは公開していません（[`bench/cases/HOLDOUT.md`](bench/cases/HOLDOUT.md)）。
数字・方法論・限界は [`bench/RESULTS.md`](bench/RESULTS.md)、コーパスの構成と分割は
[`bench/README.md`](bench/README.md) にあります。合成コーパスを自作のツールで採点した
数字なので、引用する前に RESULTS.md の限界の節を読んでください。

```bash
.venv/bin/python bench/run_bench.py    # ネットワークなし。公開リポジトリには holdout がないため dev のみ採点し、
                                       # results.json / RESULTS.md（全コーパスでの記録）は書き換えない
```

## ドリフト調査 v0（Phase 3）

`bench/drift/` は、公式 MCP レジストリのメタデータから選んだ上位 30 件（npm のダウンロード数順）と、
PyPI の無作為抽出 10 件を対象にした調査です。パッケージ実体のダウンロードやサーバーの実行はしていません。
先にカバレッジを調べ、tool 定義を実行せずに版間比較できる対象が上位 30 件中 0 件（キル基準 10% 未満）
だったため、**サーフェス・ドリフトは v0 の範囲外**とし、パッケージ・ドリフト（版数履歴・integrity の有無・
取り下げ版など）だけを集計しました。結果は [`bench/drift/DRIFT.md`](bench/drift/DRIFT.md)、取得元・取得日時は
`bench/drift/summary.json` にあります。取得した生データ（`raw/`）は再配布用ではないため、公開リポジトリには含めていません。

## Phase 1 の限界

- **振る舞いは保証しません。** 一致しているのは宣言（サーフェス）と同一性（パッケージ）です。
- **http サーバーは記録済みサーフェス（`--surface`）を取り込むだけで、実際には接続しません。**
  リモートの実体は常に「検証不能」（終了コード 2）です。
- **セッション中の差し替えは検知しません。** 列挙した後に `notifications/tools/list_changed`
  で tool を差し替えたり、相手によって返す内容を変えたりするサーバーは、検知の対象外です。
  CapLock が見るのは、列挙した時点のスナップショットだけです。
- **列挙したプロセスとパッケージの結び付きは、利用者の指定に依存します。** `--launch` で
  起動したコマンドが、解決したアーカイブそのものであることは検証しません。lockfile には
  `surface.method`（`launch-override` / `launch-config` / `recorded`）を記録して、
  そのことを明示します。
- 版数を上げることは、サーフェスが変わらなければ info（終了コード 0）です。新しい版数の
  コードの中身はレビューしません（版数を変えた設定の変更として、PR レビューの対象になります）。
- docker のダイジェストをオンラインで解決する機能はありません（`--online` でも記録なしになります）。
  設定に `@sha256:` で固定するか、`--registry` で記録を渡してください。
- inputSchema の意味差分は、トップレベルの properties / required までです。ネストした変更は
  `schema_changed`（パス付き）として一括で報告します。
- 命令的な文言の検出は、既知の単純なパターンだけです。言い換えられた tool poisoning は、
  `description_changed`（medium）としてしか現れない可能性があります。

Phase 2 で追加した限界:
- 同じ (server, tool, code, field) を持つ複数の finding（例: 同じ説明文に命令的文言のパターンが 3 つ）は、
  SARIF では同じ fingerprint になり、code scanning では 1 つの alert にまとまります。
- PR コメントは GitHub の上限に合わせて 65,000 文字で切り詰めます（全文はジョブサマリと SARIF にあります）。
- Action の動作は、`ci.yml` の手順をローカルで再現して確かめたものです。GitHub 上ではまだ実行していません。

Phase 3 で追加した限界:
- 証跡パックは無署名です。検出できるのは生成後の改竄だけで、出所は証明しません。
- Bench v0 は合成コーパスで、オペレータもラベルも CapLock の作者が書いたものです。dev の数字は特に
  楽観的に出ます。holdout で外したのは、言い換えた命令文の混入（3 件）でした。
- 他ツール（Snyk Agent Scan / mcp-lock）は、同じ条件では測れなかったため「未測定」です（理由は RESULTS.md）。

## ネットワーク方針

- 既定（`--online` なし）では、ネットワークに一切アクセスしません。
- `--online` で送るのは、npm / PyPI へのパッケージ名と版数のメタデータ要求だけです。
  tool の説明文や schema を外部に送る機能は存在しません。
- テストは、`tests/conftest.py` で外向きのソケット接続をすべて失敗させる状態で実行します。

## 開発

```bash
.venv/bin/python -m pytest          # ネットワークなし。起動するのは fixture サーバーだけ
.venv/bin/python scripts/demo.py
```

構成は `CLAUDE.md` を参照してください。シナリオ A〜I の定義と期待値は
`fixtures/scenarios/*.json` にあり、テストとデモはどちらもここを参照します。

## License

Proprietary — Copyright (c) 2026 Yuta Nagao, all rights reserved.
This repository is public for evaluation only; no licence to use, copy,
modify, or distribute is granted. The project is available for
acquisition or licensing — contact via
https://nagayu-portfolio.nagayu.workers.dev/en
