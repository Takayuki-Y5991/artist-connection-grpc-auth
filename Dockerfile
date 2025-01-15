FROM rust:1.84 as builder

# Protocol Buffersのコンパイラをインストール
RUN apt-get update && \
    apt-get install -y protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY . .

# 開発依存関係も含めてビルド
RUN cargo build --all-features

# 実行用のステージ
FROM rust:1.84-slim

WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/target ./target
COPY --from=builder /usr/src/app/config ./config

# デフォルトはサーバー起動、テストの場合はコマンドで上書き
CMD ["./target/debug/grpc-auth"]