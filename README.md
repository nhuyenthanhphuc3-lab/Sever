# PhucMax Verify Server — Render Free

Backend riêng để:
- Giữ Lua source ở server, không public trực tiếp.
- Client gửi token tới `/api/verify`.
- Token có hạn sử dụng và có thể revoke.
- Có rate limit cơ bản.
- Có SHA-256 checksum.
- Endpoint `/executors/*.lua` không trả source.

## Deploy Render

1. Tạo GitHub repository và upload toàn bộ file trong ZIP này.
2. Render → Deploy a Web Service → chọn repository.
3. Render có thể tự đọc `render.yaml`.
4. Trong Environment Variables tạo:
   - `ADMIN_SECRET` = một chuỗi bí mật dài, ngẫu nhiên.
5. Deploy.

## Test

Health:
GET /health

Tạo token:
POST /api/admin/create-token
Header:
x-admin-secret: YOUR_ADMIN_SECRET

JSON:
{"days":7,"label":"test"}

Verify:
POST /api/verify
JSON:
{"token":"TOKEN_NHAN_DUOC"}

## Đưa source lên server

Có thể sửa `storage/source.lua` trước khi deploy.

Hoặc gọi:
POST /api/admin/source
Header:
x-admin-secret: YOUR_ADMIN_SECRET
JSON:
{"source":"print('hello')"}

## Quan trọng về Render Free

Thư mục local của web service không phải nơi lưu trữ dữ liệu bền vững. Nếu service restart/redeploy, token/source lưu trong `storage/` có thể mất.

Bản ZIP này phù hợp để test/deploy nhanh. Khi hệ thống chạy ổn, nên chuyển tokens và source sang database/object storage có persistence.

## Không dùng User-Agent để bảo mật

Server không coi "executor" hay "browser" dựa trên User-Agent. Bảo vệ chính là token + expiry + revoke + rate limit.

## Giới hạn cố hữu

Khi server trả Lua source dạng plaintext cho client, client có thể đọc/copy source. Không có cách server-side nào biến plaintext đã giao cho client thành tuyệt đối bí mật.
