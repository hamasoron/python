# AWS Secrets Manager Rotation - Lambda Functions

AWS Secrets Manager用のカスタムローテーションLambda関数の実装サンプルです。

本リポジトリは、**職務経歴書のポートフォリオ**として作成しており、実務で使用可能なコード品質を目指しています。

## 📋 プロジェクト概要

RDS/Aurora MySQLのパスワードを自動ローテーションするLambda関数を2種類提供します:

- **Single-User Rotation（シングルユーザー）**: マスターユーザーのパスワードをRDS API経由で更新
- **Multi-User Rotation（マルチユーザー）**: アプリケーションユーザーを交互にSQL経由で更新してゼロダウンタイムを実現

## 🗂️ ディレクトリ構成

```
secretsmanager-rotation/
├── README.md                           # このファイル
├── single-user-rotation/               # シングルユーザーローテーション
│   ├── master_rotation_function.py    # Lambda関数本体
│   ├── requirements.txt               # 依存パッケージ
│   └── README.md                      # 詳細ドキュメント
└── multi-user-rotation/                # マルチユーザーローテーション
    ├── app_rotation_function.py       # Lambda関数本体
    ├── requirements.txt               # 依存パッケージ
    └── README.md                      # 詳細ドキュメント
```

## 🚀 主な機能

### Single-User Rotation（シングルユーザーローテーション）

- RDS `modify_db_cluster` APIでマスターパスワードを直接更新
- リトライロジック実装（パスワード伝播遅延対応）
- SSL/TLS接続サポート
- 詳細なエラーハンドリングとログ出力

**使用ケース**: RDS/Auroraのマスターユーザー（admin, root等）

### Multi-User Rotation（マルチユーザーローテーション）

- 2つのアプリユーザーを交互に使用（ゼロダウンタイム）
- マスターローテーションとの並行実行対応
- 権限の自動クローン（GRANT文のパース）
- 初回セットアップ自動対応
- 最大10回リトライ（指数バックオフ）

**使用ケース**: アプリケーション用DBユーザー

## 📊 アーキテクチャ比較

| 項目 | Single-User | Multi-User |
|-----|------------|-----------|
| **対象ユーザー** | マスターユーザー | アプリケーションユーザー |
| **更新方法** | RDS API | SQL（CREATE/ALTER USER） |
| **ダウンタイム** | 数秒（パスワード伝播待ち） | ゼロ |
| **DBユーザー数** | 1つ | 2つ（交互使用） |
| **マスター権限** | 不要（IAM） | 必要（SQL実行） |
| **複雑度** | シンプル | 高（権限クローン等） |

## 🛠️ 技術スタック

- **言語**: Python 3.13
- **AWS サービス**: 
  - AWS Secrets Manager
  - AWS Lambda
  - Amazon RDS/Aurora MySQL
- **ライブラリ**: 
  - boto3（AWS SDK）
  - pymysql（MySQL接続）

## 📝 実装のポイント

### 1. エラーハンドリング

```python
# 5種類の例外を適切に処理
try:
    # メイン処理
except ClientError as e:
    # AWS API エラー
except ValueError as e:
    # パラメータ検証エラー
except pymysql.err.OperationalError as e:
    # DB接続・認証エラー
except pymysql.err.MySQLError as e:
    # MySQL一般エラー
except Exception as e:
    # 予期しないエラー
```

### 2. SSL/TLS接続

```python
# 2つの接続モード
# Mode 1: 明示的なCA証明書指定
ssl_ca=ca_bundle_path

# Mode 2: システムデフォルトCA証明書（推奨）
ssl_verify_cert=True, ssl_verify_identity=True
```

### 3. リトライロジック（マルチユーザー）

```python
# 指数バックオフで最大10回リトライ
for attempt in range(max_retries):
    try:
        # マスター認証情報を毎回取得（ローテーション対応）
        master_secret = get_master_secret_with_fallback(...)
        # DB接続・ユーザー更新
    except AuthError:
        retry_delay = min(retry_delay * 2, 30)  # 3s → 6s → 12s → 30s
        time.sleep(retry_delay)
```

### 4. 権限クローン（マルチユーザー）

```python
# 正規表現でGRANT文をパース
pattern = r"(GRANT .+?)\s+TO\s+['\"]?(\w+)['\"]?@['\"]?([^'\"]+)['\"]?(.*?)(?:;)?$"

# 新ユーザーに適用
target_grant = f"{parsed['grant_clause']} TO '{target_username}'@'{parsed['hostname']}'"
```

## 🔧 デプロイ手順

### 1. 依存パッケージのインストール

```bash
cd single-user-rotation/  # または multi-user-rotation/
mkdir python
pip install -r requirements.txt -t python/
zip -r pymysql-layer.zip python/
```

### 2. Lambda Layerの作成

```bash
aws lambda publish-layer-version \
  --layer-name pymysql \
  --zip-file fileb://pymysql-layer.zip \
  --compatible-runtimes python3.11 python3.12
```

### 3. Lambda関数のデプロイ

**シングルユーザーローテーションの場合:**

```bash
zip master-rotation.zip master_rotation_function.py

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

**マルチユーザーローテーションの場合:**

```bash
zip app-rotation.zip app_rotation_function.py

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

### 4. Secrets Managerへの登録

```bash
aws secretsmanager rotate-secret \
  --secret-id my-rds-secret \
  --rotation-lambda-arn arn:aws:lambda:ap-northeast-1:123456789012:function:single-user-rotation \
  --rotation-rules AutomaticallyAfterDays=30
```

## 📖 ドキュメント

各ローテーション戦略の詳細は、それぞれのREADME.mdを参照してください:

- [Single-User Rotation 詳細](./single-user-rotation/README.md)
- [Multi-User Rotation 詳細](./multi-user-rotation/README.md)

## 🔒 セキュリティ

- **IAM最小権限の原則**: 必要な権限のみを付与
- **SSL/TLS暗号化**: RDS接続は必ず暗号化
- **パスワード強度**: 32文字、大文字小文字数字記号を含む
- **ログ管理**: パスワードはログに記録しない
- **バージョン管理**: AWSPREVIOUS で緊急ロールバック可能

## 🧪 テスト

### 手動ローテーションテスト

```bash
# Secrets Managerで即座にローテーション実行
aws secretsmanager rotate-secret \
  --secret-id my-rds-secret \
  --rotate-immediately
```

### CloudWatch Logsでの確認

```bash
# ログストリームを確認
aws logs tail /aws/lambda/single-user-rotation --follow
```

### 期待されるログ出力

```
[INFO] Master rotation event received: {"Step": "createSecret", ...}
[INFO] Successfully created new AWSPENDING version...
[INFO] Setting master user password using RDS modify-db-cluster API...
[INFO] Master password updated successfully...
[INFO] Testing connection with new master password...
[INFO] Successfully connected with new master password...
[INFO] Master secret rotation completed successfully
```

## 🐛 トラブルシューティング

### よくある問題と解決策

| 問題 | 原因 | 解決策 |
|-----|------|-------|
| 認証エラー（1045） | パスワード伝播遅延 | 待機時間を増やす（10→15秒） |
| タイムアウト | VPC/SG設定 | ポート3306許可、NAT GW確認 |
| InvalidDBClusterStateFault | RDS更新中 | メンテナンスウィンドウ回避 |
| MASTER_SECRET_ARN未設定 | 環境変数未設定 | Lambda環境変数に追加 |

詳細は各ディレクトリのREADME.mdを参照してください。

## 📚 参考資料

- [AWS Secrets Manager - Rotation Lambda Functions](https://docs.aws.amazon.com/ja_jp/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html)
- [AWS RDS - ModifyDBCluster API](https://docs.aws.amazon.com/ja_jp/AmazonRDS/latest/APIReference/API_ModifyDBCluster.html)
- [PyMySQL Documentation](https://pymysql.readthedocs.io/)
- [MySQL GRANT Statement](https://dev.mysql.com/doc/refman/8.0/en/grant.html)

## 💡 学んだこと・工夫した点

### 1. 並行ローテーション対応（マルチユーザー）

マスターユーザーとアプリユーザーのローテーションが同時実行される場合を想定し、フォールバックロジック（AWSPENDING → AWSCURRENT）とリトライ機構を実装しました。

### 2. 正規表現を使った権限クローン

MySQLの`SHOW GRANTS`の出力を正規表現でパースし、新ユーザーに権限を自動適用する仕組みを実装しました。

### 3. 初回セットアップの自動化

ユーザーが存在しない初回ローテーション時には、デフォルト権限を自動付与する機能を追加し、手動セットアップを不要にしました。

### 4. 詳細なログ出力

本番運用を想定し、ローテーションの各ステップで詳細なログを出力。トラブルシューティングを容易にしました。

## 👤 作成者

**職務経歴書用ポートフォリオ**

- **職種**: インフラエンジニア（SRE）
- **経験年数**: 4年（AWS実務2.5年）
- **専門領域**: AWS運用自動化、可観測性向上、MTTR削減

### 関連スキル

- **IaC**: Terraform, CloudFormation
- **CI/CD**: GitHub Actions
- **監視**: CloudWatch, X-Ray
- **言語**: Python, Bash
- **AWS認定**: 
  - AWS Certified Solutions Architect - Associate
  - （追加取得予定: Professional, Specialty）

## 📄 ライセンス

このコードはポートフォリオ用のサンプル実装です。

自由に参考にしていただいて構いませんが、本番環境での使用は各自の責任で十分にテストの上ご利用ください。

---

**Last Updated**: 2025年11月

**Status**: ✅ Production Ready（本番利用可能レベル）

