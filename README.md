# PyBit - Ứng dụng Download BitTorrent

## 1. Tổng Quan Ứng Dụng

### Tác giả

* **Phan Nguyễn Hữu Phước** - Sinh viên năm 3 ngành Khoa học Máy tính, Trường Đại học Bách Khoa TP.HCM - Đại học Quốc gia TPHCM (HCMUT - VNU)

### Giới thiệu sơ về BitTorrent

BitTorrent là một giao thức chia sẻ file ngang hàng (P2P) được thiết kế để phân phối dữ liệu hiệu quả. Thay vì tải file từ một máy chủ trung tâm, người dùng tải các phần của file từ nhiều người dùng khác ("peer") cùng lúc, giúp tăng tốc độ tải và giảm tải cho máy chủ.

### Tính năng chính đã hiện thực

* **Tải file Torrent:** Ứng dụng cho phép tải các file được chia sẻ thông qua giao thức BitTorrent.
* **Tạo file Torrent:** Ứng dụng có khả năng tạo ra các file .torrent từ một file nguồn cho trước để chia sẻ với peer khác thông qua internet
* **Kết nối với Tracker:** Ứng dụng có thể giao tiếp với tracker để lấy danh sách các peer có chứa các phần của file cần tải
* **Quản lý Peer:** Ứng dụng quản lý kết nối với nhiều peer để tải dữ liệu đồng thời
* **Chia nhỏ và ghép mảnh:** File được chia thành các mảnh nhỏ hơn để tải xuống song song từ nhiều peer và sau đó ghép lại thành file hoàn chỉnh
* **Xác thực dữ liệu:** Ứng dụng xác thực tính toàn vẹn của các mảnh dữ liệu tải xuống bằng cách sử dụng hash SHA1
* **Giao diện đồ họa (GUI):** Ứng dụng có giao diện đồ họa cho phép người dùng tương tác một cách trực quan
* **Hiển thị thông tin tải xuống:** Ứng dụng hiển thị tên file, kích thước, tiến trình, tốc độ tải và số lượng peers

### Công nghệ đã sử dụng

* **Python:** Ngôn ngữ lập trình chính để xây dựng ứng dụng
* **Tkinter:** Thư viện để xây dựng giao diện đồ họa người dùng (GUI)
* **bencodepy:** Thư viện để mã hóa và giải mã dữ liệu Bencode (định dạng dữ liệu được sử dụng trong file .torrent và giao tiếp với tracker)
* **requests:** Thư viện để thực hiện các yêu cầu HTTP (ví dụ: giao tiếp với tracker)
* **hashlib:** Thư viện để tính toán hash SHA1 (sử dụng để xác thực dữ liệu)
* **socket:** Thư viện để lập trình socket (giao tiếp mạng)
* **threading:** Thư viện để quản lý các luồng (ví dụ: tải xuống đồng thời)
* 
## 2. Hướng dẫn cài đặt và chạy app

### Yêu cầu

* **Python 3.6 trở lên**
* **Các thư viện được liệt kê trong `requirements.txt`**

### Cài đặt

1.  **Cài đặt Python:** Đảm bảo bạn đã cài đặt Python 3.6 trở lên trên hệ thống của mình.
2.  **Cài đặt các thư viện:**
    * Mở terminal hoặc command prompt.
    * Di chuyển đến thư mục chứa file `requirements.txt`.
    * Chạy lệnh: `pip install -r requirements.txt`

### Chạy ứng dụng

1.  Mở terminal hoặc command prompt.
2.  Di chuyển đến thư mục chứa file `main.py`.
3.  Chạy lệnh: `python main.py` [cite: 1]
4.  Giao diện đồ họa của ứng dụng sẽ hiện lên, cho phép bạn chọn file .torrent và thư mục lưu.

## 3. Hạn chế và tính năng thực hiện trong tương lai

### Hạn chế **Ngây thơ**: Trừ một số hiện thực hoá chuẩn tuân theo BEP3, phần còn lại của ứng dụng phía trên có cách hiện thực "ngây thơ" và đơn giản nhất có thể

### Tính năng sẽ thực hiện trong tương lai

* **Hỗ trợ Upload:** Hiện tại ứng dụng mới chỉ hỗ trợ tải xuống. Trong tương lai, ứng dụng sẽ hỗ trợ upload dữ liệu cho các peer khác.
* **DHT (Distributed Hash Table):** Cải thiện khả năng tìm kiếm peer mà không cần tracker trung tâm.
* **Magnet URI:** Hỗ trợ tải torrent bằng Magnet URI thay vì chỉ từ file .torrent.
* **Tối ưu hóa tốc độ tải:** Cải thiện hiệu suất tải xuống bằng cách tối ưu hóa việc chọn peer, quản lý kết nối và xử lý block.
* **Giao diện người dùng nâng cao:** Thêm nhiều thông tin chi tiết về quá trình tải, cho phép quản lý hàng đợi tải xuống, v.v.

## 4. Một chút thông tin về Tracker để hoàn thiện ứng dụng

Tracker là một máy chủ đóng vai trò trung gian trong giao thức BitTorrent. Khi tải một file .torrent, ứng dụng của client sẽ liên hệ với tracker được chỉ định trong file đó để lấy danh sách các peer hiện đang có các phần của file bạn muốn tải

Phần trên chỉ là phía Client nên chưa thể thật sự hoạt động, tác giả sẽ thực hiện Tracker trong tương lai (không) gần =))
Thông tin liên lạc: phanhuuphuoc101@gmail.com 

