# 快鸽视联 RTC 服务端 SDK

为企业业务后台提供 Go 和 PHP 接入能力：查询当前应用的 License 库存，并签发短期播放 / 续期 `view_token`。

> 当前版本用于受控联调。真实播放还需要设备云签发并经 RTC 信任的 `device_grant`；SDK 测试通过不代表设备授权或画面链路已完成联调。

## 接入前准备

1. 在快鸽视联管理台创建应用，由平台管理员向该应用发放 License。
2. 业务后台安全保存该应用的 AppKey 和 AppSecret，并管理本应用的 License 与设备分配关系。
3. 每次观看前验证用户身份、设备绑定或有效分享以及业务权限，并通过设备云取得与 AppKey、用户和设备一致的 `device_grant`。
4. 在可信业务服务器中使用本 SDK 签发 `view_token`。H5 / App 将两份短期凭证提交 RTC。

SDK 不负责用户登录、设备归属或分享判断、License 分配、设备云证明签发、播放器及连接保活。AppSecret 与设备云私钥不能放入 H5、小程序或移动端；`view_token` 是可读取的签名数据，`sub` 使用不含手机号的稳定用户标识。

## Go

需要 Go 1.18 或以上。首次从 GitHub 使用：

```sh
go get github.com/zhanshuoliang/kuaige-rtc-sdk/go/viewtokensigner@main
go get github.com/zhanshuoliang/kuaige-rtc-sdk/go/licenseclient@main
```

### 签发播放 Token

```go
import (
    "os"
    "github.com/zhanshuoliang/kuaige-rtc-sdk/go/viewtokensigner"
)

token, expiresAt, err := viewtokensigner.Issue(os.Getenv("RTC_APP_SECRET"), viewtokensigner.Request{
    AppKey:     os.Getenv("RTC_APP_KEY"),
    LicenseID:  assignedLicenseID, // 后台按本应用及设备的授权结果选择
    DeviceSN:   authorizedDeviceSN,
    Subject:    authorizedOpaqueUserID,
    Purpose:    "play",
    TTLSeconds: 300,
})
// 检查 err；将 token 和 expiresAt 返回给已认证的业务调用方。
```

Token 在本地签名，不查询设备在线状态或自动核验授权。每次播放、重试和续期都要生成新 Token。续期使用 `Purpose: "renew"`，并设置当前活动的 `SessionID`；续期前需重新核验业务权限。

### 查询应用 License

```go
import (
    "context"
    "os"
    "github.com/zhanshuoliang/kuaige-rtc-sdk/go/licenseclient"
)

page, err := licenseclient.QueryPage(context.Background(), nil,
    os.Getenv("RTC_APP_KEY"), os.Getenv("RTC_APP_SECRET"), 0, 100)
// 检查 err；处理 page.Licenses，并按 page.NextCursor 继续查询。
```

如果需要判断 HTTP 状态，可使用 `errors.As(err, &status)` 获取 `*licenseclient.HTTPError` 的 `StatusCode`。错误不会附带下游响应体或签名头。

## PHP

需要 64 位 PHP 7.4 或以上及 `json`、`hash`、`curl` 扩展；当前自动化验证环境为 PHP 8.3。可通过 Composer 使用 GitHub VCS 仓库：

```sh
composer config repositories.kuaige-rtc vcs https://github.com/zhanshuoliang/kuaige-rtc-sdk.git
composer require kuaige/rtc-sdk:dev-main
```

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use function Kuaige\Rtc\issueViewToken;
use function Kuaige\Rtc\queryLicensePage;

$appKey = getenv('RTC_APP_KEY');
$appSecret = getenv('RTC_APP_SECRET');

$result = issueViewToken($appKey, $appSecret, $assignedLicenseID,
    $authorizedDeviceSN, $authorizedOpaqueUserID, 'play');
// 检查异常；仅将 $result['token'] 和 $result['expires_at'] 返回给已认证的调用方。

$page = queryLicensePage($appKey, $appSecret, 0, 100);
// 处理 $page['licenses']，按 $page['next_cursor'] 分页。
```

续期使用 `issueViewToken(..., 'renew', $currentSessionID, 300)`；播放时 session ID 必须为空。每次签发都会生成新的随机标识。

## 使用短期凭证

业务后台完成权限验证后，向 H5 / App 提供新签发的 `view_token` 和可信设备云返回的 `device_grant`。直播向 RTC 提交：

```http
POST https://live.kuaige.cloud/rtc/v1/applications/webrtc/play
Content-Type: application/json

{"view_token":"<play token>","device_grant":"<device grant>"}
```

回放使用同一设备对应的 License，并按设备回放流程额外携带 `replay_nonce`。续期请求 `/rtc/v1/applications/webrtc/renew`，携带新的 `purpose=renew` Token、有效的 `device_grant`、当前 `peer_id` 和 `peer_token`。具体会话和错误处理以平台接口约定为准；不能把所有冲突都当作设备占用。

默认 Token 有效期 300 秒，可设置 60–900 秒；服务端还有会话有效期限制，初次提交时两份凭证中较早者至少应剩余 60 秒。签发和播放前检查 License 与设备云授权仍有效。设备云证明必须与 Token 的 AppKey、用户和 SN 完全一致。

License 查询只返回调用应用已发放的库存，不建立设备绑定。按 `next_cursor` 分页到 `null`；定期从 0 重新扫描。某次查询失败时，不要据此清空已有库存或解绑设备。

## 安全与测试

- 在服务端使用原始 AppSecret 字符串，不做 Base64 解码；不要写入源码、日志、URL 或客户端。
- 不要记录完整 Token、设备云证明、签名头和用户敏感数据。通过 HTTPS 传输并保持系统时间准确。
- 播放重试使用新 Token；不要重放已使用的 Token，也不要复用旧会话的续期 Token。
- 如无设备云证明或 RTC 未配置可信公钥，新厂商播放必须拒绝；不能回退到绕过授权的接口。

```sh
go test ./go/...
php php/tests/rtc_test.php
```

测试使用合成数据，不会连接真实设备。支持或接入问题请联系快鸽视联平台管理员。

## 许可

本 SDK 源码使用 [MIT License](LICENSE)。RTC 平台服务、设备权限和 License 的使用仍以对应服务约定为准。
