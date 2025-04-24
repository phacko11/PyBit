import sys
import time
import threading
import weakref

# Thư viện GUI - Cần cài đặt: pip install PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget,
    QPushButton, QListWidget, QListWidgetItem, QProgressBar, QLabel,
    QFileDialog, QLineEdit, QHBoxLayout
)
from PySide6.QtCore import Qt, Signal, QObject, Slot

# Thư viện BitTorrent - Cần cài đặt python-libtorrent
# Việc cài đặt có thể phức tạp, tham khảo tài liệu libtorrent
# Ví dụ: pip install libtorrent (có thể cần build tools)
# Hoặc cài từ package manager hệ thống (ví dụ: sudo apt install python3-libtorrent)
try:
    import libtorrent as lt
except ImportError:
    print("Lỗi: Không tìm thấy thư viện libtorrent.")
    print("Hãy đảm bảo bạn đã cài đặt python-libtorrent.")
    print("Tham khảo: https://www.libtorrent.org/python_binding.html")
    sys.exit(1)

# --- Lớp Backend Quản lý Libtorrent (Chạy trong luồng riêng) ---

class LibtorrentWorker(QObject):
    """
    Lớp này quản lý phiên libtorrent và chạy trong một luồng riêng biệt.
    Nó phát ra tín hiệu để cập nhật GUI một cách an toàn.
    """
    # Tín hiệu để gửi cập nhật trạng thái torrent đến GUI
    # tuple chứa: info_hash (hex), tên, tiến trình (0-1000), trạng thái (str)
    torrent_status_update = Signal(tuple)
    # Tín hiệu để gửi thông báo lỗi đến GUI
    error_signal = Signal(str)
    # Tín hiệu khi torrent được thêm thành công
    torrent_added_signal = Signal(str) # Gửi info_hash (hex)

    def __init__(self):
        super().__init__()
        self.session = None
        self.torrent_handles = {} # Lưu trữ các torrent_handle theo info_hash (hex)
        self._running = False
        self._alert_thread = None

    def start_session(self):
        """Khởi tạo và bắt đầu phiên libtorrent."""
        try:
            # Cấu hình cơ bản cho session
            settings = {
                'listen_interfaces': '0.0.0.0:6881', # Cổng lắng nghe mặc định
                'enable_dht': True,
                'enable_upnp': True,
                'enable_natpmp': True,
                # Thêm các cài đặt khác nếu cần
                # 'user_agent': 'MyPythonTorrentClient/0.1',
            }
            self.session = lt.session(settings)
            self._running = True

            # Bắt đầu luồng xử lý cảnh báo (alerts)
            self._alert_thread = threading.Thread(target=self._alert_loop, daemon=True)
            self._alert_thread.start()
            print("Libtorrent session đã bắt đầu.")

        except Exception as e:
            self.error_signal.emit(f"Lỗi khởi tạo session: {e}")
            self._running = False

    def stop_session(self):
        """Dừng phiên libtorrent và luồng xử lý cảnh báo."""
        self._running = False
        if self._alert_thread:
            self._alert_thread.join() # Đợi luồng kết thúc

        # Lưu trạng thái session (ví dụ: trạng thái DHT) nếu cần
        # state = self.session.save_state()
        # with open("session.state", "wb") as f:
        #     f.write(lt.write_session_params_buf(state))

        # Lưu dữ liệu resume cho từng torrent
        for handle in self.torrent_handles.values():
             if handle.is_valid() and handle.has_metadata():
                 handle.save_resume_data(lt.save_resume_flags_t.save_info_dict) # Cần xử lý alert save_resume_data_alert

        self.session = None # Giải phóng session
        print("Libtorrent session đã dừng.")

    def _alert_loop(self):
        """Vòng lặp chạy trong luồng riêng để xử lý cảnh báo từ libtorrent."""
        print("Luồng xử lý cảnh báo bắt đầu.")
        while self._running and self.session:
            self.session.wait_for_alert(1000) # Đợi tối đa 1 giây
            alerts = self.session.pop_alerts()
            for alert in alerts:
                self._handle_alert(alert)
            # Ngủ một chút để tránh chiếm CPU quá nhiều (tùy chọn)
            # time.sleep(0.1)
        print("Luồng xử lý cảnh báo kết thúc.")

    def _handle_alert(self, alert):
        """Xử lý các loại cảnh báo khác nhau."""
        alert_type = type(alert)

        # Cảnh báo khi torrent được thêm (cho async_add_torrent)
        # if alert_type == lt.add_torrent_alert:
        #     handle = alert.handle
        #     if alert.error.value() == 0 and handle.is_valid():
        #         info_hash_hex = str(handle.info_hashes().v1) # Hoặc v2 nếu dùng
        #         self.torrent_handles[info_hash_hex] = handle
        #         self.torrent_added_signal.emit(info_hash_hex)
        #         print(f"Torrent đã được thêm: {handle.status().name}")
        #         # Yêu cầu lưu resume data ban đầu
        #         handle.save_resume_data(lt.save_resume_flags_t.save_info_dict)
        #     else:
        #         self.error_signal.emit(f"Lỗi thêm torrent: {alert.error.message()}")

        # Cảnh báo cập nhật trạng thái (thường xuyên)
        if alert_type == lt.state_update_alert:
            for status in alert.status: # state_update_alert chứa danh sách status
                if status.handle.is_valid():
                    info_hash_hex = str(status.info_hashes().v1) # Hoặc v2
                    if info_hash_hex in self.torrent_handles:
                        s = status
                        progress = int(s.progress * 1000) # 0-1000 cho QProgressBar
                        state_str = ['queued', 'checking', 'downloading metadata',
                                     'downloading', 'finished', 'seeding', 'allocating',
                                     'checking fastresume'][s.state]
                        name = s.name if s.name else info_hash_hex # Lấy tên nếu có
                        status_tuple = (info_hash_hex, name, progress, state_str)
                        self.torrent_status_update.emit(status_tuple)

        # Cảnh báo khi torrent hoàn thành tải xuống
        elif alert_type == lt.torrent_finished_alert:
            handle = alert.handle
            if handle.is_valid():
                print(f"\nTorrent hoàn thành: {handle.status().name}")
                # Yêu cầu lưu resume data khi hoàn thành
                handle.save_resume_data(lt.save_resume_flags_t.save_info_dict)

        # Cảnh báo khi dữ liệu resume đã sẵn sàng để lưu
        elif alert_type == lt.save_resume_data_alert:
            handle = alert.handle
            if handle.is_valid():
                resume_data = lt.write_resume_data_buf(alert.params)
                info_hash_hex = str(handle.info_hashes().v1)
                try:
                    with open(f"{info_hash_hex}.fastresume", "wb") as f:
                        f.write(resume_data)
                    print(f"Đã lưu resume data cho: {info_hash_hex}")
                except Exception as e:
                    self.error_signal.emit(f"Lỗi lưu resume data cho {info_hash_hex}: {e}")

        # Cảnh báo lỗi lưu resume data
        elif alert_type == lt.save_resume_data_failed_alert:
            handle = alert.handle
            if handle.is_valid():
                self.error_signal.emit(f"Lỗi lưu resume data: {alert.error.message()}")

        # Cảnh báo lỗi chung
        elif isinstance(alert, (lt.torrent_error_alert, lt.peer_error_alert, lt.tracker_error_alert)):
             self.error_signal.emit(f"Lỗi Torrent/Peer/Tracker: {alert.message()}")

        # Xử lý các loại cảnh báo khác nếu cần (metadata_received_alert, etc.)
        # elif alert_type == lt.metadata_received_alert:
        #     handle = alert.handle
        #     if handle.is_valid():
        #         print(f"Đã nhận metadata cho: {handle.status().name}")
        #         # Yêu cầu lưu resume data lần đầu khi có metadata
        #         handle.save_resume_data(lt.save_resume_flags_t.save_info_dict)

    @Slot(str) # Slot để nhận đường dẫn file.torrent từ GUI
    def add_torrent_file(self, file_path):
        """Thêm torrent từ tệp.torrent."""
        if not self.session:
            self.error_signal.emit("Session chưa được khởi tạo.")
            return
        try:
            params = lt.add_torrent_params()
            # Đọc thông tin từ file.torrent
            info = lt.torrent_info(file_path)
            params.ti = info
            params.save_path = '.' # Thư mục lưu trữ (có thể thay đổi)

            # Kiểm tra xem có resume data không
            info_hash_hex = str(info.info_hashes().v1)
            resume_file = f"{info_hash_hex}.fastresume"
            try:
                with open(resume_file, "rb") as f:
                    resume_data = f.read()
                    params = lt.read_resume_data(resume_data, params)
                    print(f"Đã tải resume data cho: {info_hash_hex}")
            except FileNotFoundError:
                print(f"Không tìm thấy resume data cho: {info_hash_hex}")
            except Exception as e:
                 self.error_signal.emit(f"Lỗi đọc resume data cho {info_hash_hex}: {e}")


            # Thêm torrent vào session (đồng bộ - blocking)
            # Lưu ý: add_torrent có thể chặn nếu đang kiểm tra file
            # Cân nhắc dùng async_add_torrent và xử lý add_torrent_alert
            handle = self.session.add_torrent(params)

            if handle.is_valid():
                self.torrent_handles[info_hash_hex] = handle
                self.torrent_added_signal.emit(info_hash_hex) # Thông báo cho GUI
                print(f"Đã yêu cầu thêm torrent: {handle.status().name if handle.status().has_metadata else info_hash_hex}")
                # Yêu cầu cập nhật trạng thái ban đầu
                self.session.post_torrent_updates()
            else:
                 self.error_signal.emit("Lỗi: Không thể thêm torrent (handle không hợp lệ).")

        except RuntimeError as e:
            self.error_signal.emit(f"Lỗi thêm torrent file '{file_path}': {e}")
        except Exception as e:
             self.error_signal.emit(f"Lỗi không xác định khi thêm torrent: {e}")

    @Slot(str) # Slot để nhận magnet link từ GUI
    def add_magnet_link(self, magnet_link):
        """Thêm torrent từ liên kết magnet."""
        if not self.session:
            self.error_signal.emit("Session chưa được khởi tạo.")
            return
        try:
            params = lt.parse_magnet_uri(magnet_link)
            params.save_path = '.' # Thư mục lưu trữ

            # Kiểm tra resume data (cần info_hash từ magnet)
            info_hash_hex = str(params.info_hashes.v1) # Hoặc v2
            resume_file = f"{info_hash_hex}.fastresume"
            try:
                with open(resume_file, "rb") as f:
                    resume_data = f.read()
                    params = lt.read_resume_data(resume_data, params)
                    print(f"Đã tải resume data cho magnet: {info_hash_hex}")
            except FileNotFoundError:
                print(f"Không tìm thấy resume data cho magnet: {info_hash_hex}")
            except Exception as e:
                 self.error_signal.emit(f"Lỗi đọc resume data cho magnet {info_hash_hex}: {e}")


            handle = self.session.add_torrent(params)

            if handle.is_valid():
                self.torrent_handles[info_hash_hex] = handle
                self.torrent_added_signal.emit(info_hash_hex)
                print(f"Đã yêu cầu thêm magnet: {info_hash_hex}")
                self.session.post_torrent_updates()
            else:
                 self.error_signal.emit("Lỗi: Không thể thêm magnet (handle không hợp lệ).")

        except RuntimeError as e:
            self.error_signal.emit(f"Lỗi thêm magnet link '{magnet_link}': {e}")
        except Exception as e:
             self.error_signal.emit(f"Lỗi không xác định khi thêm magnet: {e}")

    @Slot(str) # Slot để tạm dừng torrent
    def pause_torrent(self, info_hash_hex):
        if info_hash_hex in self.torrent_handles:
            handle = self.torrent_handles[info_hash_hex]
            if handle.is_valid():
                handle.pause(lt.torrent_handle.graceful_pause)
                print(f"Đã yêu cầu tạm dừng: {info_hash_hex}")
                self.session.post_torrent_updates() # Yêu cầu cập nhật trạng thái

    @Slot(str) # Slot để tiếp tục torrent
    def resume_torrent(self, info_hash_hex):
         if info_hash_hex in self.torrent_handles:
            handle = self.torrent_handles[info_hash_hex]
            if handle.is_valid():
                handle.resume()
                print(f"Đã yêu cầu tiếp tục: {info_hash_hex}")
                self.session.post_torrent_updates()

    @Slot(str) # Slot để xóa torrent
    def remove_torrent(self, info_hash_hex, delete_files=False):
         if info_hash_hex in self.torrent_handles:
            handle = self.torrent_handles[info_hash_hex]
            if handle.is_valid():
                flags = lt.session.delete_files if delete_files else lt.session.no_flags
                self.session.remove_torrent(handle, flags)
                print(f"Đã yêu cầu xóa torrent: {info_hash_hex} (Xóa file: {delete_files})")
                del self.torrent_handles[info_hash_hex]
            else:
                 # Nếu handle không valid nhưng vẫn còn trong dict, xóa nó đi
                 del self.torrent_handles[info_hash_hex]


# --- Lớp Giao diện Người dùng Chính ---

class TorrentClientGUI(QMainWindow):
    """Lớp giao diện chính của ứng dụng."""

    # Tín hiệu để yêu cầu backend thêm torrent (an toàn luồng)
    request_add_torrent_file = Signal(str)
    request_add_magnet_link = Signal(str)
    request_pause_torrent = Signal(str)
    request_resume_torrent = Signal(str)
    request_remove_torrent = Signal(str, bool) # info_hash, delete_files

    def __init__(self, worker):
        super().__init__()
        self.setWindowTitle("Python BitTorrent Client (Basic)")
        self.setGeometry(100, 100, 800, 600)

        self.worker = worker # Tham chiếu đến backend worker

        # --- Tạo các thành phần GUI ---
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Khu vực thêm torrent
        self.add_layout = QHBoxLayout()
        self.magnet_input = QLineEdit()
        self.magnet_input.setPlaceholderText("Dán liên kết magnet vào đây")
        self.add_magnet_button = QPushButton("Thêm Magnet")
        self.add_file_button = QPushButton("Thêm File.torrent")
        self.add_layout.addWidget(self.magnet_input)
        self.add_layout.addWidget(self.add_magnet_button)
        self.add_layout.addWidget(self.add_file_button)
        self.layout.addLayout(self.add_layout)

        # Danh sách hiển thị torrent
        self.torrent_list_widget = QListWidget()
        self.layout.addWidget(self.torrent_list_widget)

        # Các nút điều khiển torrent được chọn
        self.control_layout = QHBoxLayout()
        self.pause_button = QPushButton("Tạm dừng")
        self.resume_button = QPushButton("Tiếp tục")
        self.remove_button = QPushButton("Xóa")
        self.control_layout.addWidget(self.pause_button)
        self.control_layout.addWidget(self.resume_button)
        self.control_layout.addWidget(self.remove_button)
        self.layout.addLayout(self.control_layout)

        # Nhãn trạng thái/lỗi
        self.status_label = QLabel("Trạng thái: Sẵn sàng")
        self.layout.addWidget(self.status_label)

        # --- Kết nối tín hiệu và khe cắm ---

        # Kết nối nút GUI với các yêu cầu gửi đến worker
        self.add_file_button.clicked.connect(self.select_torrent_file)
        self.add_magnet_button.clicked.connect(self.add_magnet_from_input)
        self.pause_button.clicked.connect(self.pause_selected_torrent)
        self.resume_button.clicked.connect(self.resume_selected_torrent)
        self.remove_button.clicked.connect(self.remove_selected_torrent)

        # Kết nối tín hiệu yêu cầu từ GUI đến các slot của worker
        self.request_add_torrent_file.connect(self.worker.add_torrent_file)
        self.request_add_magnet_link.connect(self.worker.add_magnet_link)
        self.request_pause_torrent.connect(self.worker.pause_torrent)
        self.request_resume_torrent.connect(self.worker.resume_torrent)
        self.request_remove_torrent.connect(self.worker.remove_torrent)


        # Kết nối tín hiệu từ worker đến các slot cập nhật GUI
        self.worker.torrent_status_update.connect(self.update_torrent_status_display)
        self.worker.error_signal.connect(self.display_error)
        self.worker.torrent_added_signal.connect(self.add_torrent_to_list)

        # Lưu trữ các widget con cho từng torrent item theo info_hash
        self.torrent_item_widgets = {} # {info_hash: {'item': QListWidgetItem, 'progress': QProgressBar, 'status_label': QLabel}}

    def select_torrent_file(self):
        """Mở hộp thoại để chọn tệp.torrent."""
        file_path, _ = QFileDialog.getOpenFileName(self, "Chọn tệp.torrent", "", "Torrent Files (*.torrent)")
        if file_path:
            self.status_label.setText(f"Đang yêu cầu thêm: {file_path}")
            self.request_add_torrent_file.emit(file_path) # Gửi tín hiệu đến worker

    def add_magnet_from_input(self):
        """Lấy link magnet từ ô input và yêu cầu thêm."""
        magnet_link = self.magnet_input.text().strip()
        if magnet_link:
            self.status_label.setText(f"Đang yêu cầu thêm magnet...")
            self.request_add_magnet_link.emit(magnet_link)
            self.magnet_input.clear() # Xóa ô input sau khi gửi
        else:
             self.display_error("Vui lòng nhập liên kết magnet.")

    def get_selected_info_hash(self):
        """Lấy info_hash của torrent đang được chọn trong danh sách."""
        selected_items = self.torrent_list_widget.selectedItems()
        if selected_items:
            item = selected_items
            # Lấy info_hash được lưu trữ trong dữ liệu của item
            return item.data(Qt.UserRole)
        return None

    def pause_selected_torrent(self):
        info_hash = self.get_selected_info_hash()
        if info_hash:
            self.request_pause_torrent.emit(info_hash)
        else:
            self.display_error("Vui lòng chọn một torrent để tạm dừng.")

    def resume_selected_torrent(self):
        info_hash = self.get_selected_info_hash()
        if info_hash:
            self.request_resume_torrent.emit(info_hash)
        else:
            self.display_error("Vui lòng chọn một torrent để tiếp tục.")

    def remove_selected_torrent(self):
        info_hash = self.get_selected_info_hash()
        if info_hash:
            # Hỏi người dùng có muốn xóa file không (ví dụ)
            # Ở đây mặc định là không xóa file
            delete_files = False
            self.request_remove_torrent.emit(info_hash, delete_files)
            # Xóa item khỏi GUI ngay lập tức (worker sẽ xóa handle sau)
            if info_hash in self.torrent_item_widgets:
                 list_item = self.torrent_item_widgets[info_hash]['item']
                 row = self.torrent_list_widget.row(list_item)
                 self.torrent_list_widget.takeItem(row)
                 del self.torrent_item_widgets[info_hash]
        else:
            self.display_error("Vui lòng chọn một torrent để xóa.")


    @Slot(str) # Slot để thêm torrent mới vào danh sách GUI
    def add_torrent_to_list(self, info_hash_hex):
        """Thêm một mục mới vào QListWidget khi torrent được thêm thành công."""
        if info_hash_hex not in self.torrent_item_widgets:
            list_item = QListWidgetItem(self.torrent_list_widget)
            list_item.setData(Qt.UserRole, info_hash_hex) # Lưu info_hash vào item

            item_widget = QWidget()
            item_layout = QVBoxLayout(item_widget)
            item_layout.setContentsMargins(5, 2, 5, 2) # Giảm khoảng cách

            name_label = QLabel(f"Torrent: {info_hash_hex} (Đang lấy metadata...)")
            progress_bar = QProgressBar()
            progress_bar.setRange(0, 1000) # Đặt dải giá trị 0-1000
            progress_bar.setValue(0)
            progress_bar.setTextVisible(True)
            progress_bar.setFormat("%p%") # Hiển thị %

            status_label = QLabel("Trạng thái: Đang chờ...")

            item_layout.addWidget(name_label)
            item_layout.addWidget(progress_bar)
            item_layout.addWidget(status_label)

            list_item.setSizeHint(item_widget.sizeHint())
            self.torrent_list_widget.addItem(list_item)
            self.torrent_list_widget.setItemWidget(list_item, item_widget)

            self.torrent_item_widgets[info_hash_hex] = {
                'item': list_item,
                'name_label': name_label,
                'progress': progress_bar,
                'status_label': status_label
            }
            print(f"Đã thêm item vào GUI cho: {info_hash_hex}")


    @Slot(tuple) # Slot nhận cập nhật trạng thái từ worker
    def update_torrent_status_display(self, status_tuple):
        """Cập nhật hiển thị cho một torrent cụ thể trong danh sách."""
        info_hash_hex, name, progress, state_str = status_tuple

        if info_hash_hex in self.torrent_item_widgets:
            widgets = self.torrent_item_widgets[info_hash_hex]
            widgets['name_label'].setText(f"Torrent: {name}")
            widgets['progress'].setValue(progress)
            widgets['status_label'].setText(f"Trạng thái: {state_str}")
            # print(f"GUI Update: {name} - {progress/10:.1f}% - {state_str}") # Debug log
        # else:
            # print(f"Warning: Nhận được cập nhật cho torrent không có trong GUI: {info_hash_hex}")
            # Có thể gọi add_torrent_to_list ở đây nếu torrent chưa có trong list
            # self.add_torrent_to_list(info_hash_hex)
            # self.update_torrent_status_display(status_tuple) # Gọi lại để cập nhật


    @Slot(str) # Slot nhận thông báo lỗi từ worker
    def display_error(self, error_message):
        """Hiển thị thông báo lỗi trên status bar."""
        print(f"LỖI: {error_message}")
        self.status_label.setText(f"Lỗi: {error_message}")

    def closeEvent(self, event):
        """Được gọi khi người dùng đóng cửa sổ."""
        print("Yêu cầu đóng ứng dụng...")
        self.worker.stop_session() # Dừng session libtorrent trước khi thoát
        event.accept() # Chấp nhận sự kiện đóng

# --- Hàm Main ---
def main():
    app = QApplication(sys.argv)

    # Tạo worker backend và di chuyển nó vào một luồng riêng
    # Điều này rất quan trọng để GUI không bị treo
    worker_thread = threading.Thread() # Tạo luồng
    worker = LibtorrentWorker()      # Tạo đối tượng worker
    # worker.moveToThread(worker_thread) # Di chuyển worker sang luồng mới (Cần QThread thay vì threading.Thread)
    # Lưu ý: Việc dùng threading.Thread trực tiếp với QObject có thể phức tạp hơn.
    # Cách đơn giản hơn cho ví dụ này là để worker chạy session trong luồng riêng của nó (như đã làm với _alert_loop)
    # và giao tiếp qua signals/slots đã được thiết kế để an toàn luồng.

    # Khởi tạo GUI và truyền worker vào
    main_window = TorrentClientGUI(worker)

    # Bắt đầu session libtorrent trong worker (sau khi GUI đã sẵn sàng nhận tín hiệu)
    worker.start_session()

    main_window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()