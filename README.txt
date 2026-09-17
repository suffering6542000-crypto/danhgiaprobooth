DANHGIAPROBOOTH - Cloudflare Pages + D1
Bản Production đã kiểm tra end-to-end

CẤU TRÚC:
- index.html: giao diện khách + trang quản trị
- functions/api/[[path]].js: API config, đánh giá, rate-limit, Turnstile, đăng nhập/đăng xuất admin
- schema.sql: tạo bảng D1 + index

CẤU HÌNH CLOUDFLARE PAGES:
1. Tạo D1 database và binding tên DB cho Pages project.
2. Chạy schema.sql trên D1.
3. Tạo secret/environment variable ADMIN_KEY với giá trị dài, ngẫu nhiên.
4. Tạo secret/environment variable RATE_LIMIT_SALT với giá trị dài, ngẫu nhiên và KHÁC ADMIN_KEY.
5. Cấu hình Cloudflare Turnstile: tạo Site Key + Secret Key và đặt TURNSTILE_SITE_KEY + TURNSTILE_SECRET_KEY.
6. Turnstile là bắt buộc để gửi review.
7. Trang quản trị: https://<ten-project>.pages.dev/?admin=1

BIẾN CẦN CÓ:
- DB: D1 binding (bắt buộc, tên biến chính xác là DB)
- ADMIN_KEY: secret (bắt buộc)
- RATE_LIMIT_SALT: secret (bắt buộc)
- TURNSTILE_SITE_KEY: variable (dùng để hiển thị Turnstile cho khách)
- TURNSTILE_SECRET_KEY: secret (bắt buộc; server từ chối review nếu chưa cấu hình)

BẢO VỆ ĐÃ THÊM:
- Validate điểm c0..c5 + overall ở server: số nguyên 1–5.
- Comment tối đa 2000 ký tự.
- Giới hạn kích thước request thực tế tối đa 10 KB trước khi JSON parse.
- Rate-limit tối đa 100 đánh giá/IP/1 giờ theo cửa sổ trượt.
- Rate-limit được kiểm tra ngay trong câu INSERT có điều kiện để giảm nguy cơ nhiều request đồng thời cùng vượt qua một COUNT(*) kiểm tra riêng.
- IP được băm bằng RATE_LIMIT_SALT, không lưu IP thô.
- User-Agent được băm và chỉ dùng để lưu dấu vết kỹ thuật.
- Admin login: tối đa 10 lần thất bại/15 phút/IP.
- Admin session dùng HttpOnly + Secure + SameSite=Strict cookie, hết hạn 8 giờ.
- Admin token được ký HMAC-SHA-256 bằng ADMIN_KEY.
- So sánh ADMIN_KEY và Admin token sử dụng safeEqual() dựa trên SHA-256 + so sánh byte cố định thay cho so sánh chuỗi trực tiếp.
- Admin phân trang: mặc định 50 bản ghi/trang, tối đa 100.
- Thống kê lấy trực tiếp từ D1.
- Comment được escape khi render ở browser.
- API trả JSON và chống MIME sniffing bằng X-Content-Type-Options: nosniff.

QUY TẮC RATE-LIMIT:
- 100 đánh giá/IP/1 giờ là quota dùng chung cho tất cả thiết bị phía sau cùng public IP/NAT.
- Rate-limit chỉ nhằm giảm flood/abuse; nó KHÔNG đồng nghĩa mỗi khách chỉ được gửi một đánh giá.
- Nếu 100 người dùng chung một mạng có cùng public IP, họ cùng dùng một quota 100 trong cửa sổ 1 giờ.

TURNSTILE:
- Frontend lấy Site Key từ /api/config.
- Frontend dùng Cloudflare Turnstile explicit rendering.
- Container Turnstile sử dụng id="turnstile-widget" để không xung đột với global window.turnstile của Cloudflare.
- Backend bắt buộc có TURNSTILE_SECRET_KEY và xác minh token trước khi lưu review.
- Token thiếu hoặc xác minh thất bại: review bị từ chối và không ghi vào D1.
- Không commit TURNSTILE_SECRET_KEY, ADMIN_KEY hoặc RATE_LIMIT_SALT vào GitHub.

ROUTING API:
- /api/config
- /api/reviews
- /api/admin-login
- /api/admin-logout
- functions/api/[[path]].js xử lý các route API trên.

KIỂM TRA TRƯỚC KHI DEPLOY:
- Backend phải nằm tại functions/api/[[path]].js.
- D1 binding phải tên DB.
- ADMIN_KEY và RATE_LIMIT_SALT phải có ở Production (Preview nếu cần).
- RATE_LIMIT_SALT phải khác ADMIN_KEY.
- Turnstile bắt buộc: Site Key phải thuộc hostname/domain đang chạy và Secret Key phải đúng cặp.
- Không cấu hình TURNSTILE_SECRET_KEY thì API review trả lỗi 503 và không lưu review.
- Không cấu hình TURNSTILE_SITE_KEY thì khách không có Turnstile token hợp lệ, nên API review cũng không lưu review.
- Không đưa secret vào index.html, README hoặc repository.
- Sau deploy, thử gửi 1 đánh giá và kiểm tra dữ liệu trong D1 + ?admin=1.
- Kiểm tra Admin login và logout.
- Kiểm tra request không có Turnstile token phải bị từ chối.

LƯU Ý VẬN HÀNH:
- Bảng admin_attempts sẽ tăng theo thời gian. Nên có chính sách dọn bản ghi cũ định kỳ nếu hệ thống chạy lâu dài.
- Nếu cần bảo vệ khu vực admin ở mức cao hơn, có thể đặt Cloudflare Access phía trước trang quản trị.
- Dữ liệu review nằm trong Cloudflare D1, không nằm trong GitHub.
- Nên export D1 định kỳ để có bản backup dữ liệu riêng.
