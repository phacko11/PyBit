import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import socket
import threading
import time
import bencodepy  
import requests    
from urllib.parse import urlencode, quote
import struct
import random
import os
from queue import Queue, Empty
import math


BLOCK_SIZE = 2**14  # Kích thước block
PEER_ID_PREFIX = b'-PY0001-' # Tiền tố ID của client 
CLIENT_PORT = 6881      # Port client 
MAX_PEER_CONNECTIONS = 10 # Số lượng kết nối peer 
CONNECT_TIMEOUT = 5    # Timeout kết nối
READ_TIMEOUT = 10       # Timeout đọc dữ liệu 
KEEP_ALIVE_INTERVAL = 110 # Gửi keep-alive 
REQUEST_TIMEOUT = 20    #Timeout cho một yêu cầu block
DEFAULT_PIECE_LENGTH = 256 * 1024

def calculate_piece_hashes(filepath, piece_length):
    """
    Đọc file và tính toán hash SHA1 cho từng mảnh.
    Trả về danh sách các hash (bytes) và tổng kích thước file.
    """
    hashes = []
    total_size = 0
    try:
        with open(filepath, 'rb') as f:
            while True:
                piece = f.read(piece_length)
                if not piece:
                    break
                total_size += len(piece)
                hashes.append(hashlib.sha1(piece).digest())

        pieces_concat = b''.join(hashes)
        return pieces_concat, total_size
    except FileNotFoundError:
        print(f"Error: File not found at {filepath}")
        return None, 0
    except IOError as e:
        print(f"Error reading file {filepath}: {e}")
        return None, 0
    except Exception as e:
        print(f"Unexpected error calculating hashes: {e}")
        return None, 0

def create_torrent_data(source_filepath, tracker_url, piece_length=DEFAULT_PIECE_LENGTH):
    """
    Tạo cấu trúc dữ liệu dictionary cho file .torrent.
    """
    if not os.path.isfile(source_filepath):
        print(f"Error: Source path is not a valid file: {source_filepath}")
        return None

    if not tracker_url:
        print("Error: Tracker URL is required.")
        return None

    print(f"Calculating piece hashes for: {source_filepath}")
    pieces_concat, file_size = calculate_piece_hashes(source_filepath, piece_length)

    if pieces_concat is None:
        return None 

    print(f"File size: {file_size} bytes")
    print(f"Piece length: {piece_length} bytes")
    print(f"Number of pieces: {len(pieces_concat) // 20}")

    #Tạo dict info
    info_dict = {
        b'name': os.path.basename(source_filepath).encode('utf-8'), 
        b'length': file_size,                                 
        b'piece length': piece_length,                        
        b'pieces': pieces_concat                           
    }

    #Tạo dict metadata 
    torrent_metadata = {
        b'announce': tracker_url.encode('utf-8'), #
        b'info': info_dict,
    }

    return torrent_metadata

def save_torrent_file(metadata, output_filepath):
    """
    Mã hóa metadata thành Bencode và lưu vào file .torrent.
    """
    if not metadata:
        print("Error: Cannot save empty metadata.")
        return False
    try:
        bencoded_data = bencodepy.encode(metadata)
        with open(output_filepath, 'wb') as f:
            f.write(bencoded_data)
        print(f"Torrent file saved successfully to: {output_filepath}")
        return True
    except (bencodepy.EncodingError, TypeError) as e:
        print(f"Error encoding torrent data: {e}")
        return False
    except IOError as e:
        print(f"Error writing torrent file {output_filepath}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error saving torrent file: {e}")
        return False

# --- Lớp chứa thông tin Torrent ---
class TorrentInfo:
    """
    Phân tích file .torrent và lưu trữ thông tin cần thiết.
    """
    def __init__(self, torrent_path):
        self.path = torrent_path
        self.metadata = None
        self.info_hash = None
        self.announce_url = None
        self.total_size = 0
        self.piece_length = 0
        self.pieces_hashes = [] 
        self.files = [] # List of dictionaries {'path': str, 'length': int, 'offset': int}
        self.num_pieces = 0
        self.is_multi_file = False

        try:
            with open(self.path, 'rb') as f:
                self.metadata = bencodepy.decode(f.read())

            info_dict = self.metadata[b'info']
            info_bencoded = bencodepy.encode(info_dict)
            self.info_hash = hashlib.sha1(info_bencoded).digest() # SHA1 hash của phần 'info'

            self.announce_url = self.metadata[b'announce'].decode('utf-8')

            self.piece_length = info_dict[b'piece length']
            pieces_concat = info_dict[b'pieces']
            if len(pieces_concat) % 20 != 0:
                raise ValueError("Invalid pieces hash length")
            self.pieces_hashes = [pieces_concat[i:i+20] for i in range(0, len(pieces_concat), 20)]
            self.num_pieces = len(self.pieces_hashes)

            # --- Thông tin File ---
            if b'files' in info_dict: #Chế độ nhiều file
                self.is_multi_file = True
                self.total_size = sum(f[b'length'] for f in info_dict[b'files'])
                current_offset = 0
                base_dir = info_dict[b'name'].decode('utf-8') 
                for f in info_dict[b'files']:
                    path_parts = [base_dir] + [p.decode('utf-8') for p in f[b'path']]
                    file_path = os.path.join(*path_parts)
                    file_length = f[b'length']
                    self.files.append({
                        'path': file_path,
                        'length': file_length,
                        'offset': current_offset #
                    })
                    current_offset += file_length
            else: 
                self.is_multi_file = False
                self.total_size = info_dict[b'length']
                file_name = info_dict[b'name'].decode('utf-8')
                self.files.append({
                    'path': file_name,
                    'length': self.total_size,
                    'offset': 0
                })

            # --- In thông tin cơ bản ---
            print("-" * 20)
            print(f"Torrent Parsed: {self.files[0]['path'] if not self.is_multi_file else info_dict[b'name'].decode('utf-8')}")
            print(f"Tracker: {self.announce_url}")
            print(f"Total Size: {self.total_size / (1024*1024):.2f} MB")
            print(f"Number of Pieces: {self.num_pieces}")
            print(f"Piece Length: {self.piece_length / 1024} KB")
            print(f"Info Hash (hex): {self.info_hash.hex()}")
            print(f"Is Multi-file: {self.is_multi_file}")
            print("-" * 20)

        except FileNotFoundError:
            raise ValueError(f"Không tìm thấy file torrent: {self.path}")
        except (bencodepy.DecodingError, KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Không thành công: {e}")
        except Exception as e:
            raise ValueError(f"Có lỗi xảy ra: {e}")

# --- Lớp quản lý mảnh (Piece) ---
class PieceManager:
    """
    Quản lý trạng thái tải xuống của từng mảnh (piece) và ghi dữ liệu vào file.
    """
    def __init__(self, torrent_info, save_path):
        self.torrent_info = torrent_info
        self.save_path = save_path
        self.num_pieces = torrent_info.num_pieces
        self.piece_length = torrent_info.piece_length
        self.total_size = torrent_info.total_size

        self.needed = list(range(self.num_pieces)) 
        self.in_progress = {}  # piece_index -> {'blocks_needed': list[(offset, length)], 'blocks_received': {offset: data}, 'peers': set()}
        self.completed = [False] * self.num_pieces 
        self.piece_data_buffer = {} 
        
        #Khóa threading
        self.lock = threading.Lock()

        self._create_files() 

    def _create_files(self):
        """Tạo file đích """
        print(f"File đích tồn tại ở: {self.save_path}")
        try:
            for file_info in self.torrent_info.files:
                full_path = os.path.join(self.save_path, file_info['path'])
                dir_name = os.path.dirname(full_path)
                if dir_name:
                    os.makedirs(dir_name, exist_ok=True)

                if not os.path.exists(full_path):
                    with open(full_path, 'wb') as f:
                        pass 

        except OSError as e:
            print(f"Có lỗi xảy ra khi tạo file đích: {e}")
            raise 

    def get_piece_size(self, piece_index):
        """Tính kích thước của một piece"""
        if piece_index < self.num_pieces - 1:
            return self.piece_length
        else:
            # Kích thước piece cuối = Tổng kích thước - kích thước các piece trước đó
            return self.total_size - (self.num_pieces - 1) * self.piece_length

    def get_blocks_for_piece(self, piece_index):
        """Trả về danh sách các (offset, length) cho các block của một piece"""
        blocks = []
        total_piece_size = self.get_piece_size(piece_index)
        offset = 0
        while offset < total_piece_size:
            block_len = min(BLOCK_SIZE, total_piece_size - offset)
            blocks.append((offset, block_len))
            offset += block_len
        return blocks

    def select_piece_to_download(self, peer_has_pieces):
        """
        Chọn một piece cần thiết mà peer này có.
        Chiến lược đơn giản: Chọn piece 'needed' đầu tiên mà peer có.
        """
        with self.lock:

            # Nếu không có piece phù hợp, chọn piece mới từ 'needed'
            random.shuffle(self.needed) 
            for index in self.needed:
                if index not in self.in_progress and peer_has_pieces[index]:
                    blocks_to_request = self.get_blocks_for_piece(index)
                    self.in_progress[index] = {
                        'blocks_needed': list(blocks_to_request), 
                        'blocks_received_count': 0,
                        'peers': set() 
                    }
                    self.piece_data_buffer[index] = {} 
                    self.needed.remove(index)
                    return index
        return None 

    def add_peer_to_piece_progress(self, piece_index, peer_id):
         """Đánh dấu peer này đang tham gia tải piece"""
         with self.lock:
            if piece_index in self.in_progress:
                self.in_progress[piece_index]['peers'].add(peer_id)

    def remove_peer_from_piece_progress(self, piece_index, peer_id):
         """Xóa peer khỏi danh sách đang tải piece"""
         with self.lock:
            if piece_index in self.in_progress:
                self.in_progress[piece_index]['peers'].discard(peer_id)

    def get_block_to_request(self, piece_index, peer_id):
         """
         Chọn một block trong piece để yêu cầu từ peer.
         """
         with self.lock:
            if piece_index in self.in_progress:
                piece_info = self.in_progress[piece_index]
                if piece_info['blocks_needed']:
                    block_offset, block_length = piece_info['blocks_needed'].pop(0)
                    return piece_index, block_offset, block_length
            return None, None, None

    def block_received(self, piece_index, begin, data):
        """
        Xử lý khi nhận được một block dữ liệu.
        Trả về: (completed_piece_index, is_valid) nếu piece hoàn thành, hoặc (None, False) nếu chưa.
        """
        with self.lock:
            if piece_index in self.in_progress and piece_index in self.piece_data_buffer:
                self.piece_data_buffer[piece_index][begin] = data
                self.in_progress[piece_index]['blocks_received_count'] += 1
                expected_blocks = len(self.get_blocks_for_piece(piece_index))
                if self.in_progress[piece_index]['blocks_received_count'] == expected_blocks:
                    print(f"[PieceMgr] Đã nhận được tất cả block từ piece {piece_index}. Đang xác thực!!")
                    piece_buffer = self.piece_data_buffer[piece_index]
                    try:
                        full_piece_data = b''.join(piece_buffer[offset] for offset in sorted(piece_buffer.keys()))
                    except KeyError:
                         print(f"!!! [PieceMgr] Có lỗi xảy ra khi tải block ở piece {piece_index}")
                         self._reset_piece_state(piece_index)
                         return piece_index, False

 
                    expected_size = self.get_piece_size(piece_index)
                    if len(full_piece_data) != expected_size:
                        print(f"!!! [PieceMgr] Xác thực kích thước file không đúng. Đang xoá file")
                        self._reset_piece_state(piece_index)
                        return piece_index, False

                    # Kiểm tra hash SHA1
                    piece_hash = hashlib.sha1(full_piece_data).digest()
                    expected_hash = self.torrent_info.pieces_hashes[piece_index]

                    if piece_hash == expected_hash:
                        print(f"[PieceMgr] Piece {piece_index} xác thực thành công")
                        try:
                             self.write_piece_to_file(piece_index, full_piece_data)
                             self.completed[piece_index] = True
                             del self.in_progress[piece_index]
                             del self.piece_data_buffer[piece_index]
                             print(f"[PieceMgr] Piece {piece_index} đang được thêm vào file")
                             return piece_index, True 
                        except IOError as e:
                             self._reset_piece_state(piece_index) 
                             return piece_index, False
                    else:
                        self._reset_piece_state(piece_index)
                        return piece_index, False 
        
        return None, False 

    def _reset_piece_state(self, piece_index):
        """Đặt lại trạng thái của piece khi có lỗi (hash sai, ghi file lỗi)"""
        with self.lock:
            if piece_index in self.in_progress:
                del self.in_progress[piece_index]
            if piece_index in self.piece_data_buffer:
                del self.piece_data_buffer[piece_index]
            if not self.completed[piece_index] and piece_index not in self.needed:
                 self.needed.append(piece_index)
            print(f"[PieceMgr] Reset state for piece {piece_index}. Added back to needed list.")


    def request_timed_out(self, piece_index, block_offset, block_length):
        """Xử lý khi một yêu cầu block bị timeout"""
        with self.lock:
            if piece_index in self.in_progress:
                self.in_progress[piece_index]['blocks_needed'].insert(0, (block_offset, block_length))

    def write_piece_to_file(self, piece_index, data):
        """Ghi dữ liệu của một piece hoàn chỉnh vào đúng vị trí trong file(s) đích"""
        global_offset_start = piece_index * self.piece_length
        data_len = len(data)
        data_ptr = 0 

        for file_info in self.torrent_info.files:
            file_start_offset = file_info['offset']
            file_end_offset = file_start_offset + file_info['length']
            file_path = os.path.join(self.save_path, file_info['path'])

            overlap_start = max(global_offset_start, file_start_offset)
            overlap_end = min(global_offset_start + data_len, file_end_offset)

            if overlap_start < overlap_end: 
                file_write_offset = overlap_start - file_start_offset
                data_read_offset = overlap_start - global_offset_start
                write_length = overlap_end - overlap_start
                data_to_write = data[data_read_offset : data_read_offset + write_length]

                try:
                    with open(file_path, 'r+b') as f:
                        f.seek(file_write_offset)
                        f.write(data_to_write)
                except FileNotFoundError:
                    raise IOError(f"File not found: {file_path}")
                except Exception as e:
                    print(f"!!! [PieceMgr] Xảy ra lỗi {e}")
                    raise 

    def get_progress(self):
        """Tính toán tiến độ tải (%) và số byte đã tải"""
        with self.lock:
            completed_count = sum(1 for c in self.completed if c)
            downloaded_bytes = 0
            for i in range(self.num_pieces):
                if self.completed[i]:
                    downloaded_bytes += self.get_piece_size(i)

            percent = (downloaded_bytes / self.total_size) * 100 if self.total_size > 0 else 0
            return completed_count, downloaded_bytes, percent

    def is_complete(self):
        """Kiểm tra xem tất cả các piece đã hoàn thành chưa"""
        with self.lock:
            return all(self.completed)

# --- Lớp xử lý kết nối Peer ---
class PeerConnection(threading.Thread):
    """
    Quản lý kết nối TCP và giao tiếp với một peer duy nhất theo Peer Wire Protocol.
    Chạy trên một luồng riêng.
    """
    def __init__(self, peer_ip, peer_port, torrent_info, piece_manager, ui_queue, client_peer_id, downloader_stop_event):
        super().__init__(daemon=True)
        self.ip = peer_ip
        self.port = peer_port
        self.torrent_info = torrent_info
        self.piece_manager = piece_manager
        self.ui_queue = ui_queue 
        self.client_peer_id = client_peer_id
        self.downloader_stop_event = downloader_stop_event 
        self.remote_peer_id = None
        self.sock = None
        self.buffer = b''
        self.last_message_sent_time = time.time() 
        self.last_message_received_time = time.time() 

        self.connected = False
        self.stopped = False 
        self.handshake_successful = False
        self.peer_choking = True     
        self.peer_interested = False 
        self.am_choking = True       
        self.am_interested = False    
        self.peer_has_pieces = [False] * torrent_info.num_pieces

        self.requested_blocks = {}
        self.max_pending_requests = 5 

        self.current_piece_index = None


    def _send_message(self, msg_type, payload=b''):
        """Đóng gói và gửi thông điệp theo Peer Wire Protocol."""
        if not self.connected or self.stopped:
            return False
        try:
            msg_len = len(payload) + 1 
            msg = struct.pack('>IB', msg_len, msg_type) + payload
            self.sock.sendall(msg)
            self.last_message_sent_time = time.time() 
            return True
        except (socket.error, BrokenPipeError, OSError) as e:
            print(f"[{self.ip}:{self.port}] Lỗi gửi message (Type {msg_type}): {e}")
            self.stop() 
            return False

    def _send_handshake(self):
        """Gửi thông điệp Handshake."""
        handshake_msg = struct.pack('>B19s8x20s20s',
                                    19, b'BitTorrent protocol', 
                                    self.torrent_info.info_hash, 
                                    self.client_peer_id)       

        try:
            self.sock.sendall(handshake_msg)
            self.last_message_sent_time = time.time()
            return True
        except (socket.error, BrokenPipeError, OSError) as e:
            print(f"[{self.ip}:{self.port}] Kết nối không thành công {e}")
            self.stop()
            return False

    def _receive_handshake(self):
        """Nhận và xác thực Handshake phản hồi."""
        try:
            self.sock.settimeout(CONNECT_TIMEOUT * 2) #Timeout handshake
            response_handshake = self.sock.recv(68) # Handshake dài 68 bytes
            self.sock.settimeout(READ_TIMEOUT) 
            self.last_message_received_time = time.time()

            if len(response_handshake) < 68:
                print(f"[{self.ip}:{self.port}] Lỗi kết nối handshake")
                return False

            pstrlen, pstr, reserved, info_hash_resp, peer_id_resp = struct.unpack('>B19s8x20s20s', response_handshake)

            # Xác thực
            if pstr != b'BitTorrent protocol':
                 print(f"[{self.ip}:{self.port}] Không đúng giao thức: {pstr}")
                 return False
            if info_hash_resp != self.torrent_info.info_hash:
                 print(f"[{self.ip}:{self.port}] Thông tin file không đúng")
                 return False

            self.remote_peer_id = peer_id_resp
            print(f"[{self.ip}:{self.port}] Kết nối thành công. Peer ID: {self.remote_peer_id.hex()}")
            self.handshake_successful = True
            return True

        except socket.timeout:
             print(f"[{self.ip}:{self.port}] Timeout")
             return False
        except (socket.error, struct.error, OSError) as e:
             print(f"[{self.ip}:{self.port}] Lỗi kết nối {e}")
             return False

    def _send_interested(self):
        """Gửi thông điệp INTERESTED"""
        if not self.am_interested:
            print(f"[{self.ip}:{self.port}] Sending INTERESTED")
            if self._send_message(2): #Interested
                self.am_interested = True

    def _send_request(self, piece_index, begin, length):
         """Gửi thông điệp REQUEST"""
         payload = struct.pack('>III', piece_index, begin, length)
         if self._send_message(6, payload): #Request
             self.requested_blocks[(piece_index, begin)] = time.time()

    def _send_keep_alive(self):
         """Gửi thông điệp keep-alive (length prefix = 0)"""
         try:
             self.sock.sendall(struct.pack('>I', 0))
             self.last_message_sent_time = time.time()
         except (socket.error, BrokenPipeError, OSError) as e:
             print(f"[{self.ip}:{self.port}] Lỗi {e}")
             self.stop()

    # --- Xử lý các loại Message nhận được ---
    def _handle_message(self, msg_id, payload):
        """Xử lý thông điệp nhận được từ peer dựa vào ID"""
        self.last_message_received_time = time.time() 

        if msg_id == 0: # Choke
            print(f"[{self.ip}:{self.port}] Received CHOKE")
            self.peer_choking = True
            if self.current_piece_index is not None:
                 self.piece_manager.remove_peer_from_piece_progress(self.current_piece_index, self.client_peer_id)
                 self.current_piece_index = None #

        elif msg_id == 1: # Unchoke
            print(f"[{self.ip}:{self.port}] Received UNCHOKE")
            self.peer_choking = False
            self._request_needed_blocks()

        elif msg_id == 2: #Interested
            self.peer_interested = True

        elif msg_id == 3: # Not Interested
            self.peer_interested = False

        elif msg_id == 4: # Have
            if len(payload) == 4:
                piece_index = struct.unpack('>I', payload)[0]
                if 0 <= piece_index < self.torrent_info.num_pieces:
                    self.peer_has_pieces[piece_index] = True
                    if not self.am_interested and self._do_i_need_this_piece(piece_index):
                         self._send_interested()
                    elif not self.peer_choking and self.am_interested and self.current_piece_index is None:
                         self._request_needed_blocks()

                else:
                    print(f"[{self.ip}:{self.port}] Lỗi message Have: {piece_index}")
            else:
                print(f"[{self.ip}:{self.port}] Lỗi Have payload size {len(payload)}")

        elif msg_id == 5: # Bitfield
            expected_len = math.ceil(self.torrent_info.num_pieces / 8)
            self._update_bitfield(payload)
            if not self.am_interested and self._check_if_interested():
                self._send_interested()


        elif msg_id == 6: #Request
            pass

        elif msg_id == 7: # Piece
            if len(payload) >= 8:
                piece_index, begin = struct.unpack('>II', payload[:8])
                block_data = payload[8:]
                block_len = len(block_data)

                request_key = (piece_index, begin)
                if request_key in self.requested_blocks:
                    del self.requested_blocks[request_key] 

                    completed_piece_idx, is_valid = self.piece_manager.block_received(piece_index, begin, block_data)

                    if completed_piece_idx is not None:
                        if is_valid:
                            self.ui_queue.put({'type': 'progress_update'})

                            if self.piece_manager.is_complete():
                                print(f"***** Tải thàn thông (peer {self.ip}:{self.port}) *****")
                                self.ui_queue.put({'type': 'download_complete'})
                        
                        if piece_index == self.current_piece_index:
                            self.current_piece_index = None

                    if not self.stopped and not self.peer_choking:
                         self._request_needed_blocks()

                else:
                    print(f"[{self.ip}:{self.port}] Lỗi tải piece {piece_index} / {begin}")

        elif msg_id == 8: # Cancel
            pass
        elif msg_id == 9: # Port (DHT)
            pass
        else:
            print(f"[{self.ip}:{self.port}] Message id không đúng {msg_id}. Payload: {payload.hex()}")

    def _update_bitfield(self, bitfield_payload):
        """Cập nhật trạng thái piece của peer dựa trên bitfield"""
        for i in range(self.torrent_info.num_pieces):
            byte_index = i // 8
            bit_index = 7 - (i % 8) 
            if (bitfield_payload[byte_index] >> bit_index) & 1:
                self.peer_has_pieces[i] = True

    def _do_i_need_this_piece(self, piece_index):
        """Kiểm tra xem client có cần piece này không"""
        with self.piece_manager.lock:
            return piece_index in self.piece_manager.needed or piece_index in self.piece_manager.in_progress

    def _check_if_interested(self):
        """kiểm tra xem peer có piece cần"""
        with self.piece_manager.lock:
            for i in range(self.torrent_info.num_pieces):
                if self.peer_has_pieces[i] and (i in self.piece_manager.needed or i in self.piece_manager.in_progress):
                    return True
        return False

    def _request_needed_blocks(self):
        """
        Chọn piece và yêu cầu các block cần thiết từ peer này
        """
        if self.peer_choking or not self.am_interested or self.stopped:
            return 

        while len(self.requested_blocks) < self.max_pending_requests:
            if self.current_piece_index is None:
                self.current_piece_index = self.piece_manager.select_piece_to_download(self.peer_has_pieces)
                if self.current_piece_index is not None:
                    self.piece_manager.add_peer_to_piece_progress(self.current_piece_index, self.client_peer_id)
                else:
                    break 
            if self.current_piece_index is not None:
                idx, offset, length = self.piece_manager.get_block_to_request(self.current_piece_index, self.client_peer_id)
                if idx is not None:
                    self._send_request(idx, offset, length)
                else:
                    self.current_piece_index = None
                    continue 
            else:
                 break


    def _check_timeouts(self):
        """Kiểm tra và xử lý các yêu cầu block bị timeout"""
        now = time.time()
        timed_out_requests = []

        for req_key, req_time in list(self.requested_blocks.items()): 
             if now - req_time > REQUEST_TIMEOUT:
                 print(f"[{self.ip}:{self.port}] Yêu cầu block {req_key} timed out")
                 timed_out_requests.append(req_key)

        for piece_index, block_offset in timed_out_requests:
             if (piece_index, block_offset) in self.requested_blocks: 
                 del self.requested_blocks[(piece_index, block_offset)]
                 # TODO cần cơ chế tốt hơn để PieceManager biết block nào timeout và cần yêu cầu lại

        if now - self.last_message_received_time > KEEP_ALIVE_INTERVAL + 60: #
             print(f"[{self.ip}:{self.port}] Kết nối timed out ")
             self.stop()


    def run(self):
        """Vòng lặp chính xử lý kết nối, handshake và tin nhắn."""
        try:
            # --- Kết nối ---
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(CONNECT_TIMEOUT)
            print(f"[{self.ip}:{self.port}] Kết nối...")
            self.sock.connect((self.ip, self.port))
            self.connected = True
            self.sock.settimeout(READ_TIMEOUT) 
            print(f"[{self.ip}:{self.port}] Đã kết nối")
            self.ui_queue.put({'type': 'peer_connected', 'peer': f"{self.ip}:{self.port}"})
            self.last_message_received_time = time.time() 

            # --- Handshake ---
            if not self._send_handshake():
                raise ConnectionError("Gửi handshake thất bại")
            if not self._receive_handshake():
                 raise ConnectionError("Nhận handshake thất bại")

            # --- Vòng lặp xử lý Message ---
            while not self.stopped and self.connected and not self.downloader_stop_event.is_set():
                now = time.time()
                if now - self.last_message_sent_time > KEEP_ALIVE_INTERVAL:
                    self._send_keep_alive()

                self._check_timeouts()
                if self.stopped: break

                # Đọc dữ liệu từ socket
                try:
                    chunk = self.sock.recv(8192)
                    if not chunk:
                        print(f"[{self.ip}:{self.port}] Kết nối bị ngắt")
                        break 
                    self.buffer += chunk
                    self.last_message_received_time = time.time() 

                except socket.timeout:
                    continue
                except (socket.error, OSError) as e:
                    print(f"[{self.ip}:{self.port}] Socket error during recv: {e}")
                    break 

                #Xử lý buffer để tách các message hoàn chỉnh
                while not self.stopped:
                    if len(self.buffer) < 4:
                        break

                    msg_len = struct.unpack('>I', self.buffer[:4])[0]

                    if msg_len == 0: 
                       
                        self.buffer = self.buffer[4:] 
                        self.last_message_received_time = time.time() 
                        continue 

                    if len(self.buffer) < 4 + msg_len:
                        break

                    msg_id = struct.unpack('>B', self.buffer[4:5])[0]
                    payload = self.buffer[5 : 4 + msg_len]
                    self.buffer = self.buffer[4 + msg_len:]

                    self._handle_message(msg_id, payload)

                    if not self.peer_choking and self.am_interested:
                         self._request_needed_blocks()


        except (socket.timeout, socket.error, ConnectionRefusedError, ConnectionAbortedError, ConnectionResetError, OSError) as e:
            print(f"[{self.ip}:{self.port}] Lỗi kết nối: {e}")
        except ConnectionError as e: 
             print(f"[{self.ip}:{self.port}] Lỗi handshake {e}")
        except Exception as e:
             print(f"[{self.ip}:{self.port}] Lỗi {e}")
             import traceback
             traceback.print_exc()
        finally:
            self.stop() 

    def stop(self):
        """Dừng kết nối, đóng socket và thông báo cho UI."""
        if self.stopped:
            return
        self.stopped = True
        self.connected = False
        #Thông báo cho PieceManager rằng peer này không còn tải piece hiện tại nữa
        if self.current_piece_index is not None:
             self.piece_manager.remove_peer_from_piece_progress(self.current_piece_index, self.client_peer_id)
             self.current_piece_index = None

        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except (OSError, socket.error):
                pass 
            try:
                self.sock.close()
            except (OSError, socket.error):
                pass
            self.sock = None
            self.ui_queue.put({'type': 'peer_disconnected', 'peer': f"{self.ip}:{self.port}"})

# --- Lớp điều phối tải xuống ---
class Downloader:
    """
    Quản lý toàn bộ quá trình tải xuống
    """
    def __init__(self, torrent_info, save_path, ui_queue):
        self.torrent_info = torrent_info
        self.save_path = save_path
        self.ui_queue = ui_queue
        self.peer_id = PEER_ID_PREFIX + os.urandom(20 - len(PEER_ID_PREFIX))
        print(f"Client Peer ID: {self.peer_id.hex()}")
        self.piece_manager = PieceManager(torrent_info, save_path)
        self.peers = [] 
        self.tracker_interval = 30 * 60 
        self.last_tracker_announce_time = 0
        self.download_thread = None
        self.stop_event = threading.Event() 
        self.active_peer_addresses = set() 
        self.lock = threading.Lock() 

    def _contact_tracker(self, event='started'):
        """
        Liên hệ tracker để lấy danh sách peer và thông báo trạng thái.
        event: 'started', 'stopped', 'completed', hoặc '' (cho update định kỳ)
        """
        if not self.torrent_info.announce_url:
            print("[Tracker] Không tìm thấy URL")
            return []

        print(f"[Tracker] Kết nối tracker ({event})...")

        _, downloaded_bytes, _ = self.piece_manager.get_progress()
        left_bytes = max(0, self.torrent_info.total_size - downloaded_bytes)

        params = {
            'info_hash': self.torrent_info.info_hash,
            'peer_id': self.peer_id,
            'port': CLIENT_PORT, 
            'uploaded': 0, 
            'downloaded': downloaded_bytes,
            'left': left_bytes,
            'compact': 1, 
            'numwant': 50, 
        }
        if event:
            params['event'] = event


        tracker_url = self.torrent_info.announce_url
        try:
            response = requests.get(tracker_url, params=params, timeout=20)
            response.raise_for_status()

            tracker_data = bencodepy.decode(response.content)

            if b'failure reason' in tracker_data:
                print(f"[Tracker] Lỗi tracker: {tracker_data[b'failure reason'].decode('utf-8', errors='ignore')}")
                return []

            self.tracker_interval = tracker_data.get(b'interval', self.tracker_interval)
            self.last_tracker_announce_time = time.time()

            peers_data = tracker_data.get(b'peers')
            found_peers = [] #Danh sách (ip, port)

            if isinstance(peers_data, bytes): #Định dạng compact
                # Mỗi peer là 6 bytes: 4 byte IP (network order), 2 byte Port (network order)
                for i in range(0, len(peers_data) - (len(peers_data) % 6), 6):
                    ip_bytes = peers_data[i:i+4]
                    port_bytes = peers_data[i+4:i+6]
                    ip = socket.inet_ntoa(ip_bytes)
                    port = struct.unpack('>H', port_bytes)[0] 
                    if port > 0 and port <= 65535:
                        found_peers.append((ip, port))

            elif isinstance(peers_data, list):
                 for p_dict in peers_data:
                    try:
                        ip_val = p_dict.get(b'ip') or p_dict.get('ip')
                        if isinstance(ip_val, bytes):
                            ip = ip_val.decode('utf-8', errors='ignore')
                        elif isinstance(ip_val, str):
                            ip = ip_val

                        port_val = p_dict.get(b'port') or p_dict.get('port')
                        if isinstance(port_val, int) and 0 < port_val <= 65535:
                            port = port_val

                        found_peers.append((ip, port))
                    except (KeyError, TypeError, ValueError) as e:
                         print(f"[Tracker] Lỗi {e}")

            return found_peers

        except requests.exceptions.Timeout:
            print(f"[Tracker] Timeout {tracker_url}")
            return []
        except Exception as e:
             print(f"[Tracker]Lỗi {e}")
             import traceback
             traceback.print_exc()
             return []

    def _manage_peers(self, potential_peers):
        """Kết nối đến các peer mới và loại bỏ các peer đã dừng"""
        with self.lock:
            alive_peers = []
            for p in self.peers:
                if p.is_alive() and not p.stopped:
                    alive_peers.append(p)
                else:
                    addr = f"{p.ip}:{p.port}"
                    if addr in self.active_peer_addresses:
                        self.active_peer_addresses.remove(addr)
            self.peers = alive_peers


            current_connections = len(self.peers)
            needed = MAX_PEER_CONNECTIONS - current_connections

            if needed <= 0:
                return
            random.shuffle(potential_peers)

            added_count = 0
            for ip, port in potential_peers:
                if needed <= 0:
                    break
                addr = f"{ip}:{port}"
                if addr not in self.active_peer_addresses:
                    print(f"[PeerMgr] Đang kết nối tới {addr}")
                    peer = PeerConnection(ip, port, self.torrent_info, self.piece_manager,
                                          self.ui_queue, self.peer_id, self.stop_event)
                    self.peers.append(peer)
                    self.active_peer_addresses.add(addr)
                    peer.start()
                    needed -= 1
                    added_count += 1


    def _download_loop(self):
        #Vòng lặp
        potential_peers = []
        try:
            potential_peers = self._contact_tracker(event='started')
            if not potential_peers and not self.stop_event.is_set():
                 print("[Downloader] Không tìm thấy peer")

            self._manage_peers(potential_peers)

            while not self.stop_event.is_set() and not self.piece_manager.is_complete():
                now = time.time()

                if now - self.last_tracker_announce_time >= self.tracker_interval:
                    new_peers = self._contact_tracker(event='') 
                    current_potential_set = set(potential_peers)
                    for p in new_peers:
                        if p not in current_potential_set:
                            potential_peers.append(p)
                            current_potential_set.add(p)
                    # TODO: Có thể cần lọc bớt potential_peers cũ không hoạt động

                self._manage_peers(potential_peers)

                woken_up = self.stop_event.wait(1.0)
                if woken_up: 
                    print("[Downloader] Kết thúc tải")
                    break

            #Kết thúc vòng lặp 
            if self.piece_manager.is_complete():
                self.ui_queue.put({'type': 'status_update', 'message': 'Tải thành công.'})
                self._contact_tracker(event='completed')
            elif self.stop_event.is_set():
                print("[Downloader] Download loop finished: STOPPED by user.")
                self.ui_queue.put({'type': 'status_update', 'message': 'Tải bị dừng'})
                self._contact_tracker(event='stopped')
                self.ui_queue.put({'type': 'download_stopped'}) 

        except Exception as e:
            print(f"[Downloader] Lỗi {e}")
            import traceback
            traceback.print_exc()
            self.ui_queue.put({'type': 'status_update', 'message': f'Error: {e}'})
        finally:
            print("[Downloader] Dừng tất cả")
            with self.lock:
                peers_to_stop = list(self.peers) 
            for peer in peers_to_stop:
                peer.stop()



    def start(self):
        """Bắt đầu tải"""
        if self.download_thread and self.download_thread.is_alive():
            print("[Downloader] Đang tải")
            return False

        self.stop_event.clear()
        self.peers = []
        self.active_peer_addresses = set()
        self.last_tracker_announce_time = 0
        try:
            self.piece_manager = PieceManager(self.torrent_info, self.save_path)
        except Exception as e:
             self.ui_queue.put({'type': 'status_update', 'message': f'Lỗi {e}'})
             return False


        self.download_thread = threading.Thread(target=self._download_loop, daemon=True)
        self.download_thread.start()
        self.ui_queue.put({'type': 'status_update', 'message': 'Bắt đầu tải'})
        return True

    def stop(self):
        """Dừng tải"""
        if not self.download_thread or not self.download_thread.is_alive():
            print("[Downloader] Đang không tải")
            return
        self.stop_event.set()

    def get_active_peers_info(self):
         """Trả về danh sách các địa chỉ peer đang hoạt động"""
         with self.lock:
             self.active_peer_addresses = {f"{p.ip}:{p.port}" for p in self.peers if p.is_alive() and not p.stopped}
             return list(self.active_peer_addresses)

# --- Giao diện đồ họa (GUI) ---
class TorrentClientGUI:
    """
    Lớp quản lý giao diện người dùng Tkinter.
    """
    def __init__(self, root):
        self.root = root
        self.root.title("PyBit by HuuPhuoc")
        self.root.geometry("700x500") 

        self.torrent_path = tk.StringVar()
        self.save_path = tk.StringVar()
        self.torrent_info = None
        self.downloader = None
        self.ui_queue = Queue() 
        self.is_downloading = False

        # --- Các thành phần UI ---

        # Frame chính để dễ quản lý layout
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Phần chọn File và Thư mục ---
        file_frame = ttk.LabelFrame(main_frame, text="Tập tin Torrent và Nơi lưu", padding="10")
        file_frame.pack(fill=tk.X, pady=5)
        file_frame.columnconfigure(1, weight=1) 

        # Chọn Torrent File
        ttk.Label(file_frame, text="File Torrent:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.torrent_entry = ttk.Entry(file_frame, textvariable=self.torrent_path, width=60)
        self.torrent_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.browse_torrent_button = ttk.Button(file_frame, text="Chọn...", command=self.browse_torrent)
        self.browse_torrent_button.grid(row=0, column=2, padx=5, pady=5)

        # Chọn Thư mục Lưu
        ttk.Label(file_frame, text="Lưu tại:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.save_entry = ttk.Entry(file_frame, textvariable=self.save_path, width=60)
        self.save_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.browse_save_button = ttk.Button(file_frame, text="Chọn...", command=self.browse_save_location)
        self.browse_save_button.grid(row=1, column=2, padx=5, pady=5)

        # --- Phần Điều khiển ---
        control_frame = ttk.Frame(main_frame, padding="5")
        control_frame.pack(fill=tk.X)

        self.start_button = ttk.Button(control_frame, text="Bắt đầu Tải", command=self.start_download, state=tk.DISABLED)
        self.start_button.pack(side=tk.LEFT, padx=10, pady=10)
        self.stop_button = ttk.Button(control_frame, text="Dừng Tải", command=self.stop_download, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=10, pady=10)

        create_frame = ttk.LabelFrame(main_frame, text="Chia sẻ file", padding="10")
        create_frame.pack(fill=tk.X, pady=10)
        create_frame.columnconfigure(1, weight=1)

        ttk.Label(create_frame, text="Tracker URL:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.tracker_url_entry = ttk.Entry(create_frame, width=50)
        # Điền sẵn URL tracker ví dụ nếu muốn
        self.tracker_url_entry.insert(0, "http://pybit.com/announce")
        self.tracker_url_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        self.create_torrent_button = ttk.Button(create_frame, text="Chọn File & Tạo Torrent...", command=self.prompt_create_torrent)
        self.create_torrent_button.grid(row=0, column=2, padx=5, pady=5)

        # --- Phần Thông tin và Tiến trình ---
        info_frame = ttk.LabelFrame(main_frame, text="Thông tin Tải xuống", padding="10")
        info_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        info_frame.columnconfigure(1, weight=1)

        # Tên File / Thư mục
        ttk.Label(info_frame, text="Tên:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        self.info_label = ttk.Label(info_frame, text="N/A", anchor="w", wraplength=550) 
        self.info_label.grid(row=0, column=1, columnspan=2, padx=5, pady=2, sticky="ew")

        # Kích thước Tổng / Đã tải
        ttk.Label(info_frame, text="Kích thước:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
        self.size_label = ttk.Label(info_frame, text="0.00 MB / 0.00 MB", anchor="w")
        self.size_label.grid(row=1, column=1, columnspan=2, padx=5, pady=2, sticky="ew")

        # Tiến trình (%)
        ttk.Label(info_frame, text="Tiến trình:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(info_frame, variable=self.progress_var, maximum=100, length=300)
        self.progress_bar.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.progress_label = ttk.Label(info_frame, text="0.0 %")
        self.progress_label.grid(row=2, column=2, padx=5, pady=5, sticky="w")


        # Tốc độ tải
        ttk.Label(info_frame, text="Tốc độ:").grid(row=3, column=0, padx=5, pady=2, sticky="w")
        self.speed_label = ttk.Label(info_frame, text="0.00 KB/s", anchor="w")
        self.speed_label.grid(row=3, column=1, columnspan=2, padx=5, pady=2, sticky="ew")

        # Số lượng Peer
        ttk.Label(info_frame, text="Peers:").grid(row=4, column=0, padx=5, pady=2, sticky="w")
        self.peers_label = ttk.Label(info_frame, text="0", anchor="w")
        self.peers_label.grid(row=4, column=1, columnspan=2, padx=5, pady=2, sticky="ew")

        # Trạng thái
        ttk.Label(info_frame, text="Trạng thái:").grid(row=5, column=0, padx=5, pady=2, sticky="w")
        self.status_message_label = ttk.Label(info_frame, text="Sẵn sàng", anchor="w")
        self.status_message_label.grid(row=5, column=1, columnspan=2, padx=5, pady=2, sticky="ew")


        # --- Biến nội bộ cho tính toán tốc độ ---
        self.last_update_time = time.time()
        self.last_downloaded_bytes = 0
        self.update_interval_ms = 1000 # Cập nhật UI mỗi giây

        # --- Bắt đầu vòng lặp cập nhật UI ---
        self.update_ui()
        # Kích hoạt nút Start nếu có đường dẫn hợp lệ ban đầu (ví dụ khi debug)
        self._validate_inputs()

        # Xử lý khi đóng cửa sổ
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def browse_torrent(self):
        """Mở hộp thoại chọn file .torrent."""
        path = filedialog.askopenfilename(
            title="Chọn file .torrent",
            filetypes=[("Torrent files", "*.torrent"), ("All files", "*.*")]
        )
        if path:
            self.torrent_path.set(path)
            self._validate_inputs()
            self.reset_ui_info()

    def browse_save_location(self):
        """Mở hộp thoại chọn thư mục lưu"""
        path = filedialog.askdirectory(title="Chọn thư mục lưu trữ")
        if path:
            self.save_path.set(path)
            self._validate_inputs()

    def _validate_inputs(self):
        """Kiểm tra đường dẫn torrent và save hợp lệ để kích hoạt nút Start"""
        t_path = self.torrent_path.get()
        s_path = self.save_path.get()
        # Chỉ kích hoạt Start nếu không đang tải và đường dẫn hợp lệ
        if not self.is_downloading and t_path and os.path.isfile(t_path) and s_path and os.path.isdir(s_path):
            self.start_button.config(state=tk.NORMAL)
        else:
            self.start_button.config(state=tk.DISABLED)

    def reset_ui_info(self):
         """Đặt lại các nhãn thông tin về trạng thái ban đầu."""
         self.info_label.config(text="N/A")
         self.size_label.config(text="0.00 MB / 0.00 MB")
         self.progress_var.set(0)
         self.progress_label.config(text="0.0 %")
         self.speed_label.config(text="0.00 KB/s")
         self.peers_label.config(text="0")
         self.status_message_label.config(text="Sẵn sàng")
         self.last_downloaded_bytes = 0
         self.last_update_time = time.time()

    def start_download(self):
        """Bắt đầu quá trình tải khi nhấn nút Start."""
        print("[GUI] Start button clicked")
        t_path = self.torrent_path.get()
        s_path = self.save_path.get()

        if not (t_path and s_path):
            messagebox.showerror("Lỗi", "Vui lòng chọn file torrent và thư mục lưu.")
            return

        if self.is_downloading:
            messagebox.showwarning("Thông báo", "Đang có tiến trình tải xuống.")
            return

        # Phân tích file torrent
        try:
            self.torrent_info = TorrentInfo(t_path)
        except ValueError as e:
            messagebox.showerror("Lỗi Torrent", f"Không thể phân tích file torrent:\n{e}")
            self.torrent_info = None
            return
        except Exception as e:
             messagebox.showerror("Lỗi", f"Lỗi không xác định khi đọc torrent:\n{e}")
             self.torrent_info = None
             return

        # Khởi tạo Downloader
        self.downloader = Downloader(self.torrent_info, s_path, self.ui_queue)

        # Cập nhật UI ban đầu trước khi bắt đầu tải
        display_name = os.path.basename(self.torrent_info.files[0]['path'])
        if self.torrent_info.is_multi_file:
             # Lấy tên thư mục gốc từ metadata nếu là multi-file
             try:
                 display_name = self.torrent_info.metadata[b'info'][b'name'].decode('utf-8')
             except KeyError:
                 display_name = os.path.basename(os.path.dirname(self.torrent_info.files[0]['path'])) # Dự phòng

        self.info_label.config(text=display_name)
        total_mb = self.torrent_info.total_size / (1024*1024)
        self.size_label.config(text=f"{total_mb:.2f} MB / 0.00 MB")
        self.reset_ui_info() # Reset các thông số khác
        self.info_label.config(text=display_name) # Đặt lại tên sau khi reset
        self.size_label.config(text=f"{total_mb:.2f} MB / 0.00 MB")


        # Bắt đầu tải
        if self.downloader.start():
            self.is_downloading = True
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.browse_torrent_button.config(state=tk.DISABLED) # Không cho đổi file khi đang tải
            self.browse_save_button.config(state=tk.DISABLED)
            self.status_message_label.config(text="Đang tải...")
        else:
            # Có lỗi khi khởi tạo Downloader (ví dụ: không tạo được file)
            messagebox.showerror("Lỗi", "Không thể bắt đầu tải xuống. Kiểm tra lỗi ở console.")
            self.downloader = None

    def stop_download(self):
        """Dừng quá trình tải khi nhấn nút Stop."""
        print("[GUI] Stop button clicked")
        if self.downloader and self.is_downloading:
            self.status_message_label.config(text="Đang dừng...")
            self.downloader.stop()
            # Không thay đổi is_downloading ngay, chờ xác nhận từ download_stopped
            self.stop_button.config(state=tk.DISABLED) # Vô hiệu hóa nút Stop ngay

    def prompt_create_torrent(self):
        """Hỏi người dùng file nguồn, nơi lưu torrent, tracker URL và tạo file .torrent."""
        if self.is_downloading:
            messagebox.showwarning("Đang tải", "Vui lòng dừng tải xuống trước khi tạo file torrent mới.")
            return

        tracker_url = self.tracker_url_entry.get().strip()
        if not tracker_url:
            messagebox.showerror("Thiếu thông tin", "Vui lòng nhập URL của Tracker.")
            return

    
        source_filepath = filedialog.askopenfilename(
            title="Chọn file để tạo torrent"
            # filetypes=[("All files", "*.*")] # Cho phép chọn mọi loại file
        )
        if not source_filepath:
            return 

        default_torrent_name = os.path.basename(source_filepath) + ".torrent"
        output_filepath = filedialog.asksaveasfilename(
            title="Lưu file .torrent",
            initialfile=default_torrent_name,
            defaultextension=".torrent",
            filetypes=[("Torrent files", "*.torrent")]
        )
        if not output_filepath:
            return 

        piece_length = DEFAULT_PIECE_LENGTH 

        self.status_message_label.config(text=f"Đang tạo torrent cho {os.path.basename(source_filepath)}...")
        self.root.update() 

        torrent_metadata = create_torrent_data(source_filepath, tracker_url, piece_length)

        if torrent_metadata:
            if save_torrent_file(torrent_metadata, output_filepath):
                messagebox.showinfo("Thành công", f"Đã tạo file torrent thành công:\n{output_filepath}")
                self.status_message_label.config(text="Tạo torrent thành công.")
            else:
                messagebox.showerror("Lỗi", "Không thể lưu file torrent. Kiểm tra lỗi ở console.")
                self.status_message_label.config(text="Lỗi khi lưu torrent.")
        else:
            messagebox.showerror("Lỗi", "Không thể tạo dữ liệu torrent. Kiểm tra lỗi ở console.")
            self.status_message_label.config(text="Lỗi khi tạo torrent.")

    def update_ui(self):
        """Đọc message từ queue và cập nhật giao diện định kỳ."""
        try:
            while True: # Xử lý hết message trong queue cho mỗi lần update
                msg = self.ui_queue.get_nowait()
                msg_type = msg.get('type')

                if msg_type == 'progress_update':
                    if self.downloader and self.downloader.piece_manager and self.torrent_info:
                         _, downloaded_bytes, percent = self.downloader.piece_manager.get_progress()
                         total_mb = self.torrent_info.total_size / (1024*1024)
                         downloaded_mb = downloaded_bytes / (1024*1024)

                         self.progress_var.set(percent)
                         self.progress_label.config(text=f"{percent:.1f} %")
                         self.size_label.config(text=f"{total_mb:.2f} MB / {downloaded_mb:.2f} MB")

                         # Tính tốc độ
                         current_time = time.time()
                         time_diff = current_time - self.last_update_time
                         # Chỉ cập nhật tốc độ nếu đủ thời gian trôi qua và có dữ liệu mới
                         if time_diff > 0.5 and downloaded_bytes > self.last_downloaded_bytes:
                             bytes_diff = downloaded_bytes - self.last_downloaded_bytes
                             speed_kbs = (bytes_diff / time_diff) / 1024
                             self.speed_label.config(text=f"{speed_kbs:.2f} KB/s")
                             self.last_update_time = current_time
                             self.last_downloaded_bytes = downloaded_bytes
                         elif time_diff > 2 and downloaded_bytes == self.last_downloaded_bytes:
                              # Nếu không có dữ liệu mới sau 2s, reset tốc độ về 0
                              self.speed_label.config(text="0.00 KB/s")


                elif msg_type == 'peer_connected' or msg_type == 'peer_disconnected':
                    if self.downloader:
                         peers_count = len(self.downloader.get_active_peers_info())
                         self.peers_label.config(text=f"{peers_count}")
                    # print(f"[GUI] Peer count updated: {peers_count}")

                elif msg_type == 'status_update':
                     self.status_message_label.config(text=f"{msg.get('message', '...')}")

                elif msg_type == 'download_complete':
                    self.status_message_label.config(text="Tải xuống hoàn tất!")
                    self.is_downloading = False
                    self.stop_button.config(state=tk.DISABLED)
                    self.browse_torrent_button.config(state=tk.NORMAL)
                    self.browse_save_button.config(state=tk.NORMAL)
                    self._validate_inputs() # Kích hoạt lại nút Start nếu cần
                    self.progress_var.set(100) # Đảm bảo đạt 100%
                    self.progress_label.config(text="100.0 %")
                    self.speed_label.config(text="0.00 KB/s") # Reset speed
                    messagebox.showinfo("Hoàn tất", "Tải torrent thành công!")

                elif msg_type == 'download_stopped':
                     self.status_message_label.config(text="Đã dừng")
                     self.is_downloading = False
                     self.stop_button.config(state=tk.DISABLED)
                     self.browse_torrent_button.config(state=tk.NORMAL)
                     self.browse_save_button.config(state=tk.NORMAL)
                     self._validate_inputs() # Kích hoạt lại nút Start
                     self.speed_label.config(text="0.00 KB/s") # Reset speed


        except Empty:
            pass
        except Exception as e:
             print(f"[GUI] Error processing UI queue message: {e}")
             import traceback
             traceback.print_exc()

        self.root.after(self.update_interval_ms, self.update_ui)

    def on_closing(self):
        """Xử lý sự kiện khi người dùng đóng cửa sổ"""
        if self.is_downloading:
            if messagebox.askyesno("Xác nhận", "Đang tải xuống. Bạn có chắc muốn thoát và dừng tải không?"):
                print("[GUI] Closing window during download...")
                if self.downloader:
                    self.downloader.stop() 
                self.root.destroy() 
            else:
                return 
        else:
            print("[GUI] Closing window.")
            self.root.destroy()


# --- Hàm main để chạy ứng dụng ---
if __name__ == "__main__":
    root = tk.Tk()

    try:
        style = ttk.Style(root)
    except tk.TclError:
        print("ttk themes not available or 'clam' theme not found.")


    app = TorrentClientGUI(root)

    root.update_idletasks() 
    window_width = root.winfo_width()
    window_height = root.winfo_height()
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x_coordinate = int((screen_width / 2) - (window_width / 2))
    y_coordinate = int((screen_height / 2) - (window_height / 2))
    root.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")

    root.mainloop()

