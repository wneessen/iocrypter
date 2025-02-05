# filecrypter

```
                          Message Format
+----------------------------------------------------------+
| scryptIterations | randSalt | randIV | cipherText | hmac |
+----------------------------------------------------------+
      (32)            (256)     (128)    (varies)    (512)
```