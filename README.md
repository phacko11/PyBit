# PyBit - Ứng dụng Download BitTorrent

## 1. Tổng Quan Ứng Dụng

### Tác giả

* **Phan Nguyễn Hữu Phước** - Sinh viên năm 3 ngành Khoa học Máy tính, Trường Đại học Bách Khoa TP.HCM - Đại học Quốc gia TPHCM (HCMUT - VNU)

### Giới thiệu sơ về BitTorrent

BitTorrent là một giao thức chia sẻ file ngang hàng (P2P) được thiết kế để phân phối dữ liệu hiệu quả. Thay vì tải file từ một máy chủ trung tâm, người dùng tải các phần của file từ nhiều người dùng khác ("peer") cùng lúc, giúp tăng tốc độ tải và giảm tải cho máy chủ.

### Tính năng chính đã hiện thực

* **Tải file Torrent:** Ứng dụng cho phép tải các file được chia sẻ thông qua giao thức BitTorrent[cite: 1].
* **Tạo file Torrent:** Ứng dụng có khả năng tạo ra các file .torrent từ một file nguồn cho trước để chia sẻ với peer khác thông qua internet[cite: 1]
* **Kết nối với Tracker:** Ứng dụng có thể giao tiếp với tracker để lấy danh sách các peer có chứa các phần của file cần tải[cite: 1]
* **Quản lý Peer:** Ứng dụng quản lý kết nối với nhiều peer để tải dữ liệu đồng thời[cite: 1].
* **Chia nhỏ và ghép mảnh:** File được chia thành các mảnh nhỏ hơn để tải xuống song song từ nhiều peer và sau đó ghép lại thành file hoàn chỉnh[cite: 1].
* **Xác thực dữ liệu:** Ứng dụng xác thực tính toàn vẹn của các mảnh dữ liệu tải xuống bằng cách sử dụng hash SHA1[cite: 1].
* **Giao diện đồ họa (GUI):** Ứng dụng có giao diện đồ họa cho phép người dùng tương tác một cách trực quan[cite: 1].
* **Hiển thị thông tin tải xuống:** Ứng dụng hiển thị tên file, kích thước, tiến trình, tốc độ tải và số lượng peers[cite: 1]

### Công nghệ đã sử dụng

* **Python:** Ngôn ngữ lập trình chính để xây dựng ứng dụng[cite: 1].
* **Tkinter:** Thư viện để xây dựng giao diện đồ họa người dùng (GUI)[cite: 1].
* **bencodepy:** Thư viện để mã hóa và giải mã dữ liệu Bencode (định dạng dữ liệu được sử dụng trong file .torrent và giao tiếp với tracker)[cite: 1, 2].
* **requests:** Thư viện để thực hiện các yêu cầu HTTP (ví dụ: giao tiếp với tracker)[cite: 1, 2].
* **hashlib:** Thư viện để tính toán hash SHA1 (sử dụng để xác thực dữ liệu)[cite: 1].
* **socket:** Thư viện để lập trình socket (giao tiếp mạng)[cite: 1].
* **threading:** Thư viện để quản lý các luồng (ví dụ: tải xuống đồng thời)[cite: 1].

## 2. Hướng dẫn cài đặt và chạy app

### Yêu cầu

* **Python 3.6 trở lên**
* **Các thư viện được liệt kê trong `requirements.txt`** [cite: 2]

### Cài đặt

1.  **Cài đặt Python:** Đảm bảo bạn đã cài đặt Python 3.6 trở lên trên hệ thống của mình.
2.  **Cài đặt các thư viện:**
    * Mở terminal hoặc command prompt.
    * Di chuyển đến thư mục chứa file `requirements.txt`.
    * Chạy lệnh: `pip install -r requirements.txt` [cite: 2]

### Chạy ứng dụng

1.  Mở terminal hoặc command prompt.
2.  Di chuyển đến thư mục chứa file `main.py`.
3.  Chạy lệnh: `python main.py` [cite: 1]
4.  Giao diện đồ họa của ứng dụng sẽ hiện lên, cho phép bạn chọn file .torrent và thư mục lưu.

## 3. Những tính năng hoàn chỉnh và sẽ thực hiện trong tương lai

### Tính năng hoàn chỉnh

* Các tính năng đã liệt kê ở mục 1.3

### Tính năng sẽ thực hiện trong tương lai

* **Hỗ trợ Upload:** Hiện tại ứng dụng mới chỉ hỗ trợ tải xuống. Trong tương lai, ứng dụng sẽ hỗ trợ upload dữ liệu cho các peer khác.
* **DHT (Distributed Hash Table):** Cải thiện khả năng tìm kiếm peer mà không cần tracker trung tâm.
* **Magnet URI:** Hỗ trợ tải torrent bằng Magnet URI thay vì chỉ từ file .torrent.
* **Tối ưu hóa tốc độ tải:** Cải thiện hiệu suất tải xuống bằng cách tối ưu hóa việc chọn peer, quản lý kết nối và xử lý block.
* **Giao diện người dùng nâng cao:** Thêm nhiều thông tin chi tiết về quá trình tải, cho phép quản lý hàng đợi tải xuống, v.v.

## 4. Một chút thông tin về Tracker để hoàn thiện ứng dụng

Tracker là một máy chủ đóng vai trò trung gian trong giao thức BitTorrent. Khi tải một file .torrent, ứng dụng của client sẽ liên hệ với tracker được chỉ định trong file đó để lấy danh sách các peer hiện đang có các phần của file bạn muốn tải[cite: 1].

Phần trên chỉ là phía Client nên chưa thể thật sự hoạt động, tác giả sẽ thực hiện Tracker trong tương lai (không) gần =))
Thông tin liên lạc: phanhuuphuoc101@gmail.com 

