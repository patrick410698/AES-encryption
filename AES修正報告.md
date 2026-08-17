# AES-128 修正報告

## 測試資料

- Plaintext：`1234567812345678`（16 bytes = 128 bits）
- Key：`1234567812345678`（16 bytes = 128 bits）
- Key 選項：`1`（AES-128）

## 修正內容

1. 將每次從輸入檔讀取的 16 bytes 複製到全域 `input`，避免 AES 實際處理全零資料。
2. 修正 `MixColumns()` 第 3、4 列錯誤寫入 `state[0]` 的問題。
3. 修正 `InverseMixColumns()` 的列索引與係數順序。
4. 新增通用 GF(2^8) 乘法，修正逆向乘法 `0x09`、`0x0A`、`0x0B`、`0x0D`、`0x0E`。
5. 在 `decrypt()` 結束時將 `state` 複製到 `output`，避免解密結果仍是零。
6. 將 `output.txt` 改用 binary 模式寫入，保留密文的 16 bytes。

## 測試方式

先編譯：

```powershell
g++ aes.cpp -o aes.exe
```

加密：

```text
1
plaintext.txt
output.txt
key.txt
1
```

解密：

```text
2
output.txt
decrypted.txt
key.txt
1
```

最後檢查：

```powershell
Format-Hex decrypted.txt
```

應看到 16 bytes：

```text
31 32 33 34 35 36 37 38 31 32 33 34 35 36 37 38
```

也就是文字：`1234567812345678`。

`output.txt` 是 AES 密文，直接用文字編輯器開啟時顯示亂碼是正常的；應使用 `Format-Hex` 查看，或用解密後的 `decrypted.txt` 查看明文。
