# BOOTSTRAP DLL 文件签名校验流程

本文记录 BOOTSTRAP DLL 中 `System.checkSignature` 的完整实现链路。它覆盖启动脚本如何调用该接口、DLL 如何注册 TJS native callback、默认 `.sig` 路径如何推导、签名文件如何解析，以及最终的 Crypto++ RSA-PSS/SHA256 校验。

本文使用的地址来自当前分析样本 `1ae7153ed25d.dll`，模块基址为 `0x10000000`。其他同类 DLL 的配置表和函数 RVA 可能不同，需要重新核对。

## 1. 启动脚本侧调用点

`sample/startup.tjs` 中签名校验位于 `_bootStrap()` 后半段：

```tjs
var exeName = System.exeName;
var extraSignatureStorage = void;
var moviePlugin = "krmovie.dll";

function extrasig(pluginName) {
    var exeBitsSuffix = (typeof System.exeBits != "undefined" && System.exeBits == 64) ? "64" : "";
    var pluginPath = System.exePath + "plugin%s/%s".sprintf(exeBitsSuffix, pluginName);
    var bresList = [];
    try {
        bresList.load("bres://./plugin");
    } catch (e) { }
    bresList = bresList[0];
    if (bresList != "") {
        var bresDomain = Storages.mountBRes(pluginPath, 1);
        if (bresDomain >= 0) {
            return ["bres://%d/%s/bin".sprintf(bresDomain, bresList), pluginPath];
        }
    }
}

if (Storages.extractStorageExt(exeName) != ".exe") {
    extraSignatureStorage = extrasig(moviePlugin);
    if (!System.checkSignature(exeName, extraSignatureStorage ? extraSignatureStorage[0] : void)) {
        failWithCorruption(Storages.extractStorageName(exeName));
    }
    exeName = Storages.chopStorageExt(exeName) + ".exe";
}
if (!System.checkSignature(exeName)) {
    failWithCorruption(Storages.extractStorageName(exeName));
}
if (extraSignatureStorage) {
    Storages.mountBRes(extraSignatureStorage[1], 0);
}
Plugins.link(moviePlugin);
```

普通路径只传一个参数：

```tjs
System.checkSignature(exeName)
```

这会让 DLL 默认读取 `{exeName}.sig`。

特殊路径会传第二参数：

```tjs
System.checkSignature(exeName, "bres://<domain>/<name>/bin")
```

第二参数被视为显式签名 storage。后续校验算法不变，只是签名 blob 的来源从默认 `{file}.sig` 变成脚本提供的 BRes 内部路径。

## 2. DLL 注册 `System.checkSignature`

BOOTSTRAP DLL 被 `Plugins.linkZ("bres://./.../bootstrap")` 加载后，会在 `RegisterSystemStorageHooks` 注册 TJS API：

| 函数 | RVA / VA | 作用 |
|------|----------|------|
| `RegisterSystemStorageHooks` | `0xFAE0` / `0x1000FAE0` | 注册和卸载 System/Storages hooks |
| `System_bootStrap_callback` | `0xEEB0` / `0x1000EEB0` | 实现 `System.bootStrap` |
| `sub_1000F3E0` | `0xF3E0` / `0x1000F3E0` | 实现 `System.checkSignature` |

关键注册动作：

```text
0x1000FB3E  v29 = System_bootStrap_callback
0x1000FB64  "bootStrap"

0x1000FB79  v30 = sub_1000F3E0
0x1000FB9F  "checkSignature"

0x1000FBD3  "System"
```

因此脚本中的 `System.checkSignature(...)` 进入 DLL 的 `sub_1000F3E0`。

## 3. 公钥和全局 verifier 初始化

签名校验器由 `System.bootStrap` 初始化阶段建立。该阶段从 DLL 配置表读取 `PUBKEY`，再调用：

```text
0x10015540  sub_10015540(FilterManager, pubkey_ptr, pubkey_len)
    -> 0x1000C3D0  sub_1000C3D0(pubkey_ptr, pubkey_len)
```

`sub_10015540` 的语义：

```cpp
if (!this[1]) {
    if (pubkey_ptr && pubkey_len)
        this[1] = sub_1000C3D0(pubkey_ptr, pubkey_len);
    else
        TVPAddImportantLog("embedded public key not found.");
}
```

`sub_1000C3D0` 创建一个 8 字节外层 holder：

```cpp
holder = operator new(8);
holder[0] = new KrkrSign::VerifierImpl;
holder[1] = L".sig";
holder[0]->LoadPublicKey(pubkey_ptr, pubkey_len);
return holder;
```

其中 `holder[1] = L".sig"` 是默认签名后缀。后续 `System.checkSignature(file)` 未提供第二参数时，会用它构造默认签名路径。

`KrkrSign::VerifierImpl` 构造函数位于 `0x10024CF0`。IDA 类型信息显示内部 Crypto++ verifier 为：

```text
CryptoPP::TF_VerifierImpl<
  CryptoPP::TF_SignatureSchemeOptions<
    CryptoPP::TF_SS<CryptoPP::RSA, CryptoPP::PSS, CryptoPP::SHA256, int>,
    CryptoPP::RSA,
    CryptoPP::PSSR_MEM<0, CryptoPP::P1363_MGF1, -1, 0, 0>,
    CryptoPP::SHA256
  >
>
```

也就是 `RSA + PSS + SHA256`。

### PUBKEY 格式

当前样本的配置表中有 `PUBKEY` 文本：

```text
-----BEGIN PUBLIC KEY-----
MIGJAoGBAMj4pBhHadu6Xm4EBq6ee3748p1lrqInHzYZgyRiMaZ3GPLyextraHW9
xTXuboncn/81Uu3f7fceSyr0X3TdD8aWUnc8lrFx7umFQJ+b/MTUSJldsvToeAOu
z86YGKrtdzxlULarErocNt4aq0Ftzno343yeh4qwNac6mL4XqEGtAgMBAAE=
-----END PUBLIC KEY-----
```

虽然 PEM 标签写作 `PUBLIC KEY`，但 Base64 载荷解码后是 Crypto++ 可直接读取的 RSA public key DER，开头为：

```text
30 81 89 02 81 81 ...
```

它不是标准 X.509 SubjectPublicKeyInfo；用部分通用库按 X.509 PEM 读取会失败。

## 4. `System.checkSignature` callback 参数处理

`sub_1000F3E0` 是 TJS callback。主要工作是把脚本参数转成 `tTJSString`，检查可选第二参数是否为空，并调用 verifier holder。

伪代码：

```cpp
int System_checkSignature(result, arg0, argc, argv) {
    tTJSString fileName(arg0);
    tTJSString sigName;

    if (argc > 0 && TJSVariantType(argv[0]) == string) {
        tTJSString tmp(argv[0]);
        sigName = tmp;
    }

    bool sigNameEmpty = sigName.IsEmpty();

    if (!g_FilterManager)
        g_FilterManager = new FilterManager();

    verifierHolder = g_FilterManager[1];
    if (!verifierHolder)
        return TJS_E_FAIL;

    optionalSig = sigNameEmpty ? NULL : &sigName;
    ok = sub_1000C3A0(verifierHolder, &fileName, optionalSig);

    if (result)
        *result = ok;
    return TJS_S_OK;
}
```

结论：

| TJS 调用 | DLL 行为 |
|----------|----------|
| `System.checkSignature(file)` | 校验 `file`，签名来源为 `file + ".sig"` |
| `System.checkSignature(file, sigStorage)` | 校验 `file`，签名来源为 `sigStorage` |
| 第二参数为空字符串或 `void` | 等同于未提供第二参数 |

## 5. 读取目标文件和签名文件

`sub_1000C3A0` 只是薄封装：

```cpp
bool sub_1000C3A0(holder, fileName, optionalSig) {
    return holder && sub_1000D2F0(holder, fileName, optionalSig);
}
```

`sub_1000D2F0` 是路径推导和文件读取层：

```cpp
bool CheckFileSignature(holder, fileName, optionalSig) {
    targetOctet = readStorageAll(fileName);       // sub_1000C870

    if (optionalSig) {
        sigStorage = *optionalSig;
    } else {
        sigStorage = fileName + holder->suffix;   // holder->suffix == ".sig"
    }

    sigOctet = readStorageAll(sigStorage);        // sub_1000C870
    ok = VerifyOctets(holder, targetOctet, sigOctet); // sub_1000D460

    Release(targetOctet);
    Release(sigOctet);
    return ok;
}
```

`readStorageAll` 对应 `sub_1000C870`，它调用 Kirikiri storage API 创建 stream，取长度，分配 buffer，一次性读取完整 storage，再封装为 `tTJSVariantOctet`。如果读取失败或长度不合法，返回 0，后续校验失败。

## 6. 核心 verifier 调用顺序

真正校验在 `sub_1000D460`：

```cpp
bool VerifyOctets(holder, targetOctet, sigOctet) {
    if (!targetOctet || !sigOctet)
        return false;

    globalVerifier = holder[0];
    if (globalVerifier && globalVerifier->HasPublicKey())
        publicKeySource = globalVerifier;
    else
        publicKeySource = NULL;

    verifier = new KrkrSign::VerifierImpl();

    if (!verifier->ImportPublicKey(publicKeySource))
        goto fail;

    sigPtr = sigOctet.GetData();
    sigLen = sigOctet.GetLength();
    if (!verifier->DecodeSignature(sigPtr, sigLen))
        goto fail;

    targetPtr = targetOctet.GetData();
    targetLen = targetOctet.GetLength();
    verifier->Update(targetPtr, targetLen);

    ok = verifier->Final();

fail:
    verifier->Release();
    return ok;
}
```

对应 vtable 槽位：

| vtable offset | 函数 | 作用 |
|---------------|------|------|
| `+0x14` | `0x1002B490` | 从全局 verifier 复制/导入公钥 |
| `+0x18` | `0x1002D5A0` | 解析签名文本，得到原始 signature bytes |
| `+0x0C` | `0x1002D9F0` | 喂入待验证文件内容 |
| `+0x10` | `0x1002B8C0` | flush/finalize 并返回校验结果 |

`sub_1000D460` 每次调用都会创建临时 verifier，再从全局 verifier 导入公钥。这样单次校验中的签名状态、消息累积状态不会污染全局对象。

## 7. `.sig` 文本解析

签名文件不是纯二进制 signature，而是文本封装：

```text
-- SIGNATURE - SHA256/PSS/RSA --
<Base64 signature>
```

`sub_1002D5A0` 的处理链：

```text
CryptoPP::StringSource(sig_text)
  -> KrkrSign::Stripper
  -> CryptoPP::Base64Decoder
  -> CryptoPP::StringSink(decoded_signature)
```

`KrkrSign::Stripper` 是一个 Crypto++ filter。它扫描输入文本，跳过前后的 `-- ... --` 分隔行，只把中间的 Base64 payload 传给下游 `Base64Decoder`。

当前游戏目录中的真实 `.sig` 文件特征：

| 文件 | `.sig` 文件长度 | Base64 长度 | 解码后长度 |
|------|-----------------|-------------|------------|
| `SabbatOfTheWitch.exe.sig` | 212 | 172 | 128 |
| `data.xp3.sig` | 212 | 172 | 128 |
| `plugin/krmovie.dll.sig` | 212 | 172 | 128 |

解码后的 128 字节 signature 对应 RSA-1024 签名长度。

## 8. RSA-PSS/SHA256 验证

`sub_1002B8C0` 执行最终校验：

1. 将 `sub_1002D5A0` 解码出的 signature 设置到 verifier。
2. 将 `sub_1002D9F0` 累积的目标文件 bytes 作为 message。
3. flush Crypto++ pipeline。
4. 读取 verifier 内部结果字节。
5. 成功返回 `true`，失败返回 `false` 并记录 `"verify failed"`。

算法参数：

| 项 | 值 |
|----|----|
| 公钥 | DLL 配置表 `PUBKEY` |
| 密钥类型 | RSA-1024 public key |
| 签名方案 | RSA-PSS |
| Hash | SHA-256 |
| MGF | MGF1(SHA-256) |
| PSS salt length | 32 |
| Signature length | 128 bytes |

可用等价伪代码表示：

```python
message = read_bytes(file)
sig_text = read_text(sig_storage)
sig = base64_decode(strip_signature_wrapper(sig_text))

hash = SHA256(message)
RSA_PSS_SHA256_verify(pubkey, hash, sig, salt_len=32)
```

## 9. `extrasig` 分支的意义

`extrasig("krmovie.dll")` 不改变签名算法。它只改变签名数据的读取位置。

普通分支：

```text
System.checkSignature(exeName)
  -> read exeName
  -> read exeName + ".sig"
  -> RSA-PSS/SHA256 verify
```

特殊分支：

```text
extra = extrasig("krmovie.dll")
System.checkSignature(exeName, extra[0])
  -> read exeName
  -> read extra[0]                  # bres://<domain>/<name>/bin
  -> RSA-PSS/SHA256 verify
```

`extrasig` 具体流程：

1. 根据 `System.exeBits` 选择 `plugin/` 或 `plugin64/`。
2. 构造 `pluginPath = System.exePath + "plugin%s/%s"`。
3. 读取 `bres://./plugin` 得到 BRes 内部资源名。
4. 用 `Storages.mountBRes(pluginPath, 1)` 临时挂载插件文件。
5. 返回 `bres://<domain>/<resource>/bin` 作为显式签名 storage。

校验通过后，脚本再执行：

```tjs
Storages.mountBRes(extraSignatureStorage[1], 0);
Plugins.link("krmovie.dll");
```

也就是说，`extrasig` 是为了非 `.exe` 启动场景先校验当前启动文件，再把 `krmovie.dll` 作为 BRes 域正式挂载和链接。

## 10. 完整调用链

```text
startup.tjs
  System.checkSignature(file [, sigStorage])
    -> sub_1000F3E0
       - 参数转 tTJSString
       - 第二参数为空则传 NULL
       - 取 g_FilterManager[1]
    -> sub_1000C3A0
    -> sub_1000D2F0
       - sub_1000C870(file) 读取目标文件
       - optionalSig ? optionalSig : file + ".sig"
       - sub_1000C870(sigStorage) 读取签名文件
    -> sub_1000D460
       - new KrkrSign::VerifierImpl
       - 导入全局 RSA 公钥
       - KrkrSign::Stripper 剥离签名文本外壳
       - CryptoPP::Base64Decoder 解码 signature
       - Update(message bytes)
       - Final()
    -> bool
```

## 11. 与 XP3/Hxv4 解密链路的关系

文件签名校验和 Hxv4 资源解密共享 BOOTSTRAP DLL、配置表和 `g_FilterManager` 生命周期，但职责不同：

| 链路 | 主要输入 | 主要输出 | 用途 |
|------|----------|----------|------|
| `System.checkSignature` | 文件 bytes、`.sig`、`PUBKEY` | bool | 启动时完整性校验 |
| `System.bootStrap` / FilterManager KDF | bootstrap text、`PARAMS`、`UNIQUE` | `drip_program.json` 对应状态 | XP3 Hxv4 和 stream filter 解密 |

`PUBKEY` 只用于签名校验，不参与 Hxv4 payload 或资源内容解密。`PARAMS`、`UNIQUE`、`WARNING` 等材料才是静态恢复 `drip_program.json` 的核心输入。
