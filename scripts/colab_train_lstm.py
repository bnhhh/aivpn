#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Mini AI VPN Gateway - MLOps Colab Training Script
Tác giả: Chuyên gia Kiến trúc Hệ thống MLOps & Deep Learning An toàn Thông tin
Mô tả:
    - Kịch bản chạy trên Google Colab để huấn luyện mô hình phát hiện chuỗi C2 Beaconing nguy hại.
    - Tích hợp bộ sinh dữ liệu giả lập (Dummy Data Generator) chất lượng cao:
        + Chuỗi Malicious (C2 Beacon): Chuỗi lặp lại tuần hoàn đơn điệu (Ví dụ: A-A-A..., A-B-A-B..., C-C-C...).
        + Chuỗi Normal (Lướt web sạch): Chuỗi ký tự ngẫu nhiên biến động cao (Ví dụ: D-R-Y-T-L...).
    - Tokenizer toán học nhất quán: ord(char) - ord('A') + 1. Không cần lưu file tokenizer cồng kềnh.
    - Xây dựng mạng LSTM: Embedding -> LSTM (32 units) -> Dense -> Dense (Sigmoid).
    - Xuất mô hình thành file model.h5 và chuyển đổi sang model.tflite siêu nhẹ cho VPN Gateway.
"""

import os
import sys
import random
import numpy as np

# Đảm bảo in UTF-8 không gặp lỗi bảng mã trên Windows PowerShell
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

# Cố gắng tắt log GPU cảnh báo của TensorFlow nếu chạy local test
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

try:
    import tensorflow as tf
    from tensorflow.keras import Sequential
    from tensorflow.keras.layers import Embedding, LSTM, Dense
except ImportError:
    print("[\033[33mWARNING\033[0m] Thiếu thư viện TensorFlow! Script này được thiết kế để chạy trên Google Colab có sẵn TensorFlow.")
    print("Nếu chạy local, hãy cài đặt bằng lệnh: pip install tensorflow")
    tf = None


def char_to_token(char: str) -> int:
    """
    Tokenizer toán học đồng nhất giữa huấn luyện và suy luận:
    Ánh xạ 27 ký tự từ 'A' đến '[' thành các số nguyên từ 1 đến 27.
    Token 0 dành riêng cho padding.
    """
    token = ord(char) - ord('A') + 1
    return max(1, min(27, token)) # Kẹp giá trị trong khoảng [1, 27]


def generate_dummy_dataset(num_samples: int = 2000, sequence_length: int = 20):
    """
    Bộ sinh dữ liệu giả lập chất lượng cao để train thử nghiệm mô hình:
    - 50% Nhãn 1 (Malicious - C2 Beaconing): Chuỗi lặp lại chu kỳ ngắn, biến động thấp.
    - 50% Nhãn 0 (Normal - Hành vi người dùng): Chuỗi ngẫu nhiên từ bảng chữ cái.
    """
    X_str = []
    y = []

    alphabet = [chr(ord('A') + i) for i in range(27)] # 'A' -> '['

    for _ in range(num_samples):
        is_malicious = random.random() > 0.5
        
        if is_malicious:
            # Sinh chuỗi Beacon tuần hoàn (Malicious)
            # Chọn ngẫu nhiên 1 hoặc 2 ký tự làm chu kỳ (Ví dụ: 'A' lặp lại, hoặc 'A-C-A-C...')
            cycle_type = random.choice([1, 2])
            if cycle_type == 1:
                char_pattern = random.choice(alphabet[:5]) # Ưu tiên các ký tự đầu (Duration nhỏ, Bytes nhẹ)
                seq = [char_pattern] * sequence_length
            else:
                char1 = random.choice(alphabet[:4])
                char2 = random.choice(alphabet[:4])
                seq = [char1 if i % 2 == 0 else char2 for i in range(sequence_length)]
            
            # Thêm một chút nhiễu ngẫu nhiên (5% cơ hội đổi ký tự) để mô hình học kháng nhiễu
            for idx in range(sequence_length):
                if random.random() < 0.05:
                    seq[idx] = random.choice(alphabet)
                    
            X_str.append(seq)
            y.append(1)
        else:
            # Sinh chuỗi ngẫu nhiên biến động cao đại diện cho lướt web sạch (Normal)
            seq = [random.choice(alphabet) for _ in range(sequence_length)]
            X_str.append(seq)
            y.append(0)

    # Tokenize dữ liệu sang dạng số nguyên
    X_tokens = []
    for seq in X_str:
        tokens = [char_to_token(c) for c in seq]
        X_tokens.append(tokens)

    return np.array(X_tokens), np.array(y)


def build_and_train_model():
    """Huấn luyện mô hình và xuất ra định dạng siêu nhẹ .h5 và .tflite."""
    if tf is None:
        print("[LỖI] TensorFlow chưa được cài đặt trên môi trường hiện tại. Không thể chạy huấn luyện.")
        return

    print("=" * 80)
    print(" BẮT ĐẦU QUY TRÌNH HUẤN LUYỆN LSTM SEQUENCE CLASSIFIER (COLAB MLOPS) ")
    print("=" * 80)

    # 1. Sinh dữ liệu giả lập
    print("\n[STEP 1] Đang sinh dữ liệu giả lập (2000 mẫu, chuỗi dài 20)...")
    X, y = generate_dummy_dataset(num_samples=2000, sequence_length=20)
    
    # Chia tập Train / Test (80% - 20%)
    split_idx = int(len(X) * 0.8)
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    
    print(f"-> Tập Train: {X_train.shape}, Tập Test: {X_test.shape}")

    # 2. Xây dựng cấu trúc mạng Neural LSTM
    print("\n[STEP 2] Khởi tạo cấu trúc mạng Neural LSTM...")
    model = Sequential([
        # Embedding: 28 từ vựng (tokens 0-27), vector đầu ra 8 chiều, chuỗi dài 20
        Embedding(input_dim=28, output_dim=8, input_length=20, name="embedding_layer"),
        # Mạng LSTM 32 Units giải mã chuỗi thời gian
        LSTM(32, return_sequences=False, name="lstm_layer"),
        # Dense trung gian
        Dense(16, activation='relu', name="dense_dense"),
        # Dense Sigmoid đầu ra phân loại nhị phân (Safe vs Malicious Probability)
        Dense(1, activation='sigmoid', name="output_layer")
    ])

    model.compile(
        optimizer='adam',
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    model.summary()

    # 3. Huấn luyện mô hình
    print("\n[STEP 3] Bắt đầu quá trình tối ưu hóa trọng số (Training epochs)...")
    model.fit(
        X_train, y_train,
        epochs=10,
        batch_size=32,
        validation_split=0.1,
        verbose=1
    )

    # 4. Đánh giá chất lượng mô hình
    print("\n[STEP 4] Đánh giá mô hình trên tập kiểm thử độc lập...")
    loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
    print(f"-> Độ chính xác kiểm thử (Test Accuracy): {accuracy * 100:.2f}%")

    # 5. Xuất mô hình Keras .h5
    model_h5_path = "lstm_model.h5"
    print(f"\n[STEP 5] Đang xuất mô hình ra định dạng Keras .h5 -> {model_h5_path}...")
    model.save(model_h5_path)

    # 6. Chuyển đổi và xuất mô hình TensorFlow Lite (.tflite) siêu nhẹ cho VPN Gateway
    model_tflite_path = "lstm_model.tflite"
    print(f"[STEP 6] Đang chuyển đổi sang TensorFlow Lite (.tflite) siêu nhẹ -> {model_tflite_path}...")
    converter = tf.lite.TFLiteConverter.from_keras_model(model)
    # Tối ưu hóa kích thước model
    converter.optimizations = [tf.lite.Optimize.DEFAULT]
    tflite_model = converter.convert()
    
    with open(model_tflite_path, "wb") as f:
        f.write(tflite_model)
        
    print(f"[\033[32mSUCCESS\033[0m] Xuất cả 2 mô hình thành công! Hãy upload file '{model_tflite_path}' lên Ubuntu VPN Gateway.")
    print("=" * 80)


if __name__ == "__main__":
    build_and_train_model()
