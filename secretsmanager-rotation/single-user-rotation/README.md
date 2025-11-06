# Single-User Rotation (シングルユーザーローテーション)

## 概要

AWS Secrets Managerのシングルユーザーローテーション戦略を実装したLambda関数です。

RDS/Aurora MySQLのマスターユーザーパスワードを自動的にローテーションし、データベースのセキュリティを強化します。

## 特徴

- **RDS API経由でのパスワード更新**: `modify_db_cluster` APIを使用してマスターパスワードを直接更新
- **4ステップローテーション**: AWS Secrets Managerの標準ローテーションフロー（createSecret → setSecret → testSecret → finishSecret）
- **リトライロジック**: パスワード伝播遅延に対応した接続テストの自動リトライ
- **SSL/TLS接続**: RDSへの暗号化通信をサポート
- **エラーハンドリング**: 詳細なログ出力と例外処理

## アーキテクチャ

### ローテーションフロー

```
┌──────────────────────────────────────────────────────────────┐
│                  Secrets Manager Rotation                     │
└──────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
┌───────────────┐  ┌──────────────┐  ┌──────────────┐
│ createSecret  │  │  setSecret   │  │ testSecret   │
│               │  │              │  │              │
│ 新パスワード  │  │  RDS API     │  │ DB接続確認   │
│ 生成・保存    │  │  パスワード  │  │ (新パスワード)│
│               │  │  更新        │  │              │
└───────────────┘  └──────────────┘  └──────────────┘
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
- 新しいパスワードを生成（AWS Secrets Manager API使用）
- AWSPENDING バージョンとして保存

#### Step 2: setSecret
- RDS `modify_db_cluster` APIでマスターパスワードを更新
- パスワード伝播待機（デフォルト: 10秒）

#### Step 3: testSecret
- 新しいパスワードでDB接続テスト
- リトライロジック（デフォルト: 3回、5秒間隔）

#### Step 4: finishSecret
- AWSPENDING を AWSCURRENT に昇格
- 旧 AWSCURRENT は自動的に AWSPREVIOUS へ

## ファイル構成

```
single-user-rotation/
├── master_rotation_function.py  # Lambda関数本体
├── requirements.txt             # 依存パッケージ（pymysql）
└── README.md                    # このファイル
```

## 必要な環境変数

### 必須
なし（全てSecrets Managerのシークレット値から取得）

### オプション

| 環境変数名 | デフォルト値 | 説明 |
|-----------|------------|------|
| `PASSWORD_LENGTH` | 32 | パスワードの長さ |
| `EXCLUDE_CHARACTERS` | `/@"'\` | パスワードから除外する文字 |
| `RDS_PASSWORD_PROPAGATION_WAIT` | 10 | RDSパスワード変更後の待機時間（秒） |
| `DB_CONNECTION_TEST_RETRIES` | 3 | 接続テストのリトライ回数 |
| `DB_CONNECTION_TEST_RETRY_DELAY` | 5 | リトライ間隔（秒） |
| `DB_CA_BUNDLE_PATH` | - | RDS CA証明書バンドルのパス（オプション） |

## シークレット構造

Secrets Managerに保存されるシークレットの形式:

```json
{
  "engine": "mysql",
  "host": "my-cluster.cluster-xxxxx.ap-northeast-1.rds.amazonaws.com",
  "port": 3306,
  "username": "admin",
  "password": "auto-generated-password",
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
      "Resource": "arn:aws:secretsmanager:*:*:secret:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "rds:ModifyDBCluster"
      ],
      "Resource": "arn:aws:rds:*:*:cluster:*"
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
zip master-rotation.zip master_rotation_function.py

# AWS CLI でデプロイ
aws lambda create-function \
  --function-name single-user-rotation \
  --runtime python3.11 \
  --role arn:aws:iam::123456789012:role/lambda-rotation-role \
  --handler master_rotation_function.lambda_handler \
  --zip-file fileb://master-rotation.zip \
  --layers arn:aws:lambda:ap-northeast-1:123456789012:layer:pymysql:1 \
  --vpc-config SubnetIds=subnet-xxxxx,SecurityGroupIds=sg-xxxxx \
  --timeout 60
```

### 3. Secrets Managerへの登録

```bash
aws secretsmanager rotate-secret \
  --secret-id my-rds-secret \
  --rotation-lambda-arn arn:aws:lambda:ap-northeast-1:123456789012:function:single-user-rotation \
  --rotation-rules AutomaticallyAfterDays=30
```

## トラブルシューティング

### 1. 認証エラー（Error 1045）

**原因**: RDSパスワード変更が伝播していない

**対策**:
- `RDS_PASSWORD_PROPAGATION_WAIT` を増やす（例: 15秒）
- `DB_CONNECTION_TEST_RETRIES` を増やす（例: 5回）

### 2. タイムアウトエラー

**原因**: Lambda VPC設定またはネットワーク問題

**対策**:
- セキュリティグループでポート3306のインバウンドを確認
- NATゲートウェイ/VPCエンドポイント設定を確認
- Lambda タイムアウト設定を延長（60秒以上推奨）

### 3. RDS API エラー（InvalidDBClusterStateFault）

**原因**: RDSクラスターが更新中またはメンテナンス中

**対策**:
- RDSクラスターのステータスを確認
- メンテナンスウィンドウを避けてローテーションをスケジュール

## セキュリティ考慮事項

1. **パスワード強度**: デフォルト32文字、大文字小文字数字記号を含む
2. **暗号化通信**: SSL/TLS必須（`ssl_verify_cert=True`）
3. **最小権限の原則**: IAMロールは必要最小限の権限のみ
4. **ログ管理**: CloudWatch Logsに詳細ログを記録（パスワードは記録しない）
5. **バージョン管理**: AWSPREVIOUS で1つ前のパスワードをロールバック可能

## 参考リソース

- [AWS Secrets Manager - Lambda Rotation Functions](https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html)
- [AWS RDS - Modify DB Cluster](https://docs.aws.amazon.com/ja_jp/AmazonRDS/latest/APIReference/API_ModifyDBCluster.html)
- [PyMySQL Documentation](https://pymysql.readthedocs.io/)

## ライセンス

このコードはポートフォリオ用のサンプル実装です。

## 作成者

職務経歴書用ポートフォリオ - AWS SRE Engineer

