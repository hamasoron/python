# Multi-User Rotation (マルチユーザーローテーション)

## 概要

AWS Secrets Managerのマルチユーザーローテーション戦略を実装したLambda関数です。

2つのアプリケーションユーザーを交互に使用することで、**ゼロダウンタイムローテーション**を実現します。

## 特徴

- **ゼロダウンタイム**: 旧ユーザーが有効なまま新ユーザーを作成・更新
- **マスターローテーションとの並行実行対応**: マスターユーザーのローテーション中でも正常に動作
- **権限の自動クローン**: 既存ユーザーの権限を新ユーザーに自動コピー
- **初回セットアップ対応**: ユーザーが存在しない場合はデフォルト権限で作成
- **リトライロジック**: 認証失敗時の自動リトライ（最大10回、指数バックオフ）
- **SSL/TLS接続**: RDSへの暗号化通信をサポート

## アーキテクチャ

### マルチユーザー戦略

```
┌────────────────────────────────────────────────────────────┐
│              Multi-User Rotation Strategy                   │
│                                                             │
│  APP_USER_1 ←→ APP_USER_2 を交互に使用                     │
│                                                             │
│  ┌──────────────┐         ┌──────────────┐                │
│  │  hamasoron1  │ ←────→ │  hamasoron2  │                │
│  │  (Active)    │         │  (Standby)   │                │
│  └──────────────┘         └──────────────┘                │
│         │                        ▲                          │
│         │  Rotation 1回目        │                          │
│         └────────────────────────┘                          │
│                                                             │
│  次回ローテーション時:                                       │
│  hamasoron2 (Active) ←→ hamasoron1 (Standby)              │
└────────────────────────────────────────────────────────────┘
```

### ローテーションフロー

```
┌─────────────────────────────────────────────────────────────┐
│                 Secrets Manager Rotation                     │
└─────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐  ┌──────────────┐  ┌──────────────┐
│ createSecret  │  │  setSecret   │  │ testSecret   │
│               │  │              │  │              │
│ ユーザー交互  │  │  SQL経由     │  │ DB接続確認   │
│ 新パスワード  │  │  ユーザー    │  │ (新ユーザー) │
│ 生成・保存    │  │  作成/更新   │  │              │
└───────────────┘  └──────────────┘  └──────────────┘
                           │
                           ├─ Master接続
                           ├─ CREATE USER / ALTER USER
                           ├─ 権限クローン (GRANT)
                           └─ COMMIT
                                        │
                                        ▼
                                ┌──────────────┐
                                │finishSecret  │
                                │              │
                                │ AWSCURRENT   │
                                │ 昇格         │
                                └──────────────┘
```

### ローテーション詳細

#### Step 1: createSecret
- AWSCURRENT シークレットを取得
- ユーザー名を交互に切り替え（USER_1 → USER_2 → USER_1 ...）
- 新しいパスワードを生成
- AWSPENDING バージョンとして保存

#### Step 2: setSecret
1. **マスター認証情報の取得**（フォールバックロジック）
   - AWSPENDING（マスターローテーション中）→ AWSCURRENT の順で取得
   
2. **DB接続（マスターユーザーとして）**
   - SSL/TLS接続確立
   - 認証失敗時は最大10回リトライ（指数バックオフ）

3. **ユーザー管理**
   - 新ユーザーが存在する場合: `ALTER USER` でパスワード更新
   - 新ユーザーが存在しない場合: `CREATE USER` + 権限クローン

4. **パスワード伝播待機**（デフォルト: 5秒）

#### Step 3: testSecret
- 新しいユーザー・パスワードでDB接続テスト
- リトライロジック（デフォルト: 3回、5秒間隔）

#### Step 4: finishSecret
- AWSPENDING を AWSCURRENT に昇格
- アプリケーションは次回接続時から新ユーザーを使用
- 旧ユーザーはAWSPREVIOUSとして保持（ロールバック可能）

## ファイル構成

```
multi-user-rotation/
├── app_rotation_function.py  # Lambda関数本体
├── requirements.txt          # 依存パッケージ（pymysql）
└── README.md                 # このファイル
```

## 必要な環境変数

### 必須

| 環境変数名 | 説明 | 例 |
|-----------|------|---|
| `MASTER_SECRET_ARN` | マスターユーザーのシークレットARN | `arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:master-secret-abc123` |
| `APP_USER_1` | 1つ目のアプリケーションユーザー名 | `hamasoron1` |
| `APP_USER_2` | 2つ目のアプリケーションユーザー名 | `hamasoron2` |

### オプション

| 環境変数名 | デフォルト値 | 説明 |
|-----------|------------|------|
| `PASSWORD_LENGTH` | 32 | パスワードの長さ |
| `EXCLUDE_CHARACTERS` | `/@"'\` | パスワードから除外する文字 |
| `DB_PASSWORD_PROPAGATION_WAIT` | 5 | DB パスワード変更後の待機時間（秒） |
| `DB_CONNECTION_TEST_RETRIES` | 3 | 接続テストのリトライ回数 |
| `DB_CONNECTION_TEST_RETRY_DELAY` | 5 | リトライ間隔（秒） |
| `DB_CA_BUNDLE_PATH` | - | RDS CA証明書バンドルのパス（オプション） |

## シークレット構造

### アプリケーションユーザーシークレット

```json
{
  "engine": "mysql",
  "host": "my-cluster.cluster-xxxxx.ap-northeast-1.rds.amazonaws.com",
  "port": 3306,
  "database": "myapp_db",
  "username": "hamasoron1",
  "password": "auto-generated-password"
}
```

### マスターユーザーシークレット

```json
{
  "engine": "mysql",
  "host": "my-cluster.cluster-xxxxx.ap-northeast-1.rds.amazonaws.com",
  "port": 3306,
  "username": "admin",
  "password": "master-password",
  "dbClusterIdentifier": "my-cluster"
}
```

## 必要なIAMポリシー

Lambda実行ロールに以下の権限が必要です:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:UpdateSecretVersionStage",
        "secretsmanager:GetRandomPassword"
      ],
      "Resource": [
        "arn:aws:secretsmanager:*:*:secret:app-secret-*",
        "arn:aws:secretsmanager:*:*:secret:master-secret-*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateNetworkInterface",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DeleteNetworkInterface"
      ],
      "Resource": "*"
    }
  ]
}
```

## ネットワーク設定

- **VPC配置**: RDSと同じVPCに配置（プライベートサブネット推奨）
- **セキュリティグループ**: RDSのセキュリティグループでLambdaからのインバウンド（ポート3306）を許可
- **RDS接続**: SSL/TLS接続を推奨

## デプロイ方法

### 1. Lambda Layer準備（pymysqlの追加）

```bash
# 依存パッケージのインストール
mkdir python
pip install -r requirements.txt -t python/

# Layerのzip作成
zip -r pymysql-layer.zip python/
rm -rf python/
```

### 2. Lambda関数のデプロイ

```bash
# Lambda関数のzip作成
zip app-rotation.zip app_rotation_function.py

# AWS CLI でデプロイ
aws lambda create-function \
  --function-name multi-user-rotation \
  --runtime python3.11 \
  --role arn:aws:iam::123456789012:role/lambda-rotation-role \
  --handler app_rotation_function.lambda_handler \
  --zip-file fileb://app-rotation.zip \
  --layers arn:aws:lambda:ap-northeast-1:123456789012:layer:pymysql:1 \
  --vpc-config SubnetIds=subnet-xxxxx,SecurityGroupIds=sg-xxxxx \
  --environment Variables="{MASTER_SECRET_ARN=arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:master-secret-abc123,APP_USER_1=hamasoron1,APP_USER_2=hamasoron2}" \
  --timeout 60
```

### 3. Secrets Managerへの登録

```bash
aws secretsmanager rotate-secret \
  --secret-id app-secret \
  --rotation-lambda-arn arn:aws:lambda:ap-northeast-1:123456789012:function:multi-user-rotation \
  --rotation-rules AutomaticallyAfterDays=30
```

## ローテーションタイムライン

### 初回ローテーション（USER_1 → USER_2）

| タイミング | DBユーザー状態 | Secrets Manager状態 |
|-----------|--------------|-------------------|
| 開始前 | `root` のみ | AWSCURRENT: `hamasoron1` (DBには未存在) |
| setSecret | `root`, `hamasoron2` 作成 | AWSCURRENT: `hamasoron1`, AWSPENDING: `hamasoron2` |
| finishSecret | `root`, `hamasoron2` | AWSCURRENT: `hamasoron2`, AWSPREVIOUS: `hamasoron1` |

### 2回目ローテーション（USER_2 → USER_1）

| タイミング | DBユーザー状態 | Secrets Manager状態 |
|-----------|--------------|-------------------|
| 開始前 | `root`, `hamasoron2` | AWSCURRENT: `hamasoron2` |
| setSecret | `root`, `hamasoron2`, `hamasoron1` 作成 | AWSCURRENT: `hamasoron2`, AWSPENDING: `hamasoron1` |
| finishSecret | `root`, `hamasoron2`, `hamasoron1` | AWSCURRENT: `hamasoron1`, AWSPREVIOUS: `hamasoron2` |

### 3回目以降（USER_1 → USER_2）

| タイミング | DBユーザー状態 | Secrets Manager状態 |
|-----------|--------------|-------------------|
| 開始前 | `root`, `hamasoron1`, `hamasoron2` | AWSCURRENT: `hamasoron1` |
| setSecret | `hamasoron2` のパスワードのみ更新 | AWSCURRENT: `hamasoron1`, AWSPENDING: `hamasoron2` |
| finishSecret | 両ユーザー存在 | AWSCURRENT: `hamasoron2`, AWSPREVIOUS: `hamasoron1` |

## 並行マスターローテーション対応

### 問題

マスターユーザーとアプリユーザーのローテーションが同時に発生すると、アプリローテーションがマスター認証に失敗する可能性があります。

### 解決策

1. **フォールバックロジック**
   - `get_master_secret_with_fallback()` 関数が自動的に最新の認証情報を取得
   - AWSPENDING（ローテーション中）→ AWSCURRENT（通常時）の順で試行

2. **リトライ戦略**
   - 認証失敗時は最大10回リトライ
   - 指数バックオフ（3秒 → 6秒 → 12秒 → ... 最大30秒）

3. **事前待機**
   - マスターのAWSPENDINGを検出した場合、初回接続前に8秒待機
   - RDSパスワード伝播を待つことで、不要なリトライを削減

### タイムライン例

```
時刻 | マスターローテーション                | アプリローテーション
-----|-------------------------------------|---------------------------------------
0秒  | setSecret (RDS API)                | setSecret開始
     |                                     | └─ AWSPENDING検出 → 8秒待機
8秒  | (新パスワード伝播中...)              | マスター接続試行（新パスワード使用）
     |                                     | └─ 通常は成功、失敗時はリトライ
10秒 | パスワード伝播完了（10秒待機）       | アプリユーザー更新完了
13秒 | testSecret（新パスワードで接続）     | testSecret（新アプリユーザーで接続）
```

## トラブルシューティング

### 1. 認証エラー（Error 1045） - マスター接続時

**原因**: マスターローテーションとの競合

**対策**:
- リトライロジックが自動的に対応（ログに "concurrent master rotation" と表示）
- 環境変数 `RDS_PASSWORD_PROPAGATION_WAIT` を増やす

### 2. 権限クローンエラー

**原因**: 初回セットアップ時にソースユーザーが存在しない

**対策**:
- 自動的にデフォルト権限（SELECT,INSERT,UPDATE,DELETE,CREATE,DROP）を付与
- ログに "initial setup" と表示されるのは正常動作

### 3. タイムアウトエラー

**原因**: Lambda VPC設定またはネットワーク問題

**対策**:
- セキュリティグループでポート3306のインバウンドを確認
- NATゲートウェイ/VPCエンドポイント設定を確認
- Lambda タイムアウト設定を延長（60秒以上推奨）

### 4. "MASTER_SECRET_ARN environment variable is not set"

**原因**: 必須環境変数が未設定

**対策**:
- Lambda環境変数に `MASTER_SECRET_ARN`, `APP_USER_1`, `APP_USER_2` を設定

## セキュリティ考慮事項

1. **最小権限の原則**
   - マスターユーザーはユーザー管理のみに使用
   - アプリユーザーはデータ操作のみに制限

2. **暗号化通信**: SSL/TLS必須（`ssl_verify_cert=True`）

3. **パスワード強度**: デフォルト32文字、大文字小文字数字記号を含む

4. **ログ管理**: CloudWatch Logsに詳細ログを記録（パスワードは記録しない）

5. **バージョン管理**: AWSPREVIOUS で1つ前のユーザー・パスワードをロールバック可能

## 参考リソース

- [AWS Secrets Manager - Multi-User Strategy](https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_turn-on-for-other.html)
- [AWS Secrets Manager - Lambda Rotation Functions](https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html)
- [PyMySQL Documentation](https://pymysql.readthedocs.io/)
- [MySQL GRANT Statement](https://dev.mysql.com/doc/refman/8.0/en/grant.html)

## ライセンス

このコードはポートフォリオ用のサンプル実装です。

## 作成者

職務経歴書用ポートフォリオ - AWS SRE Engineer

