#安装依赖pip install psutil pyqt5 GPUtil
import sys
import psutil
import time
from PyQt5.QtCore import Qt, QTimer, QPoint
from PyQt5.QtGui import QFont, QColor, QPainter
from PyQt5.QtWidgets import QApplication, QLabel, QWidget, QVBoxLayout, QHBoxLayout, QSizePolicy, QDesktopWidget

try:
    import GPUtil
except ImportError:
    GPUtil = None


class SystemMonitor(QWidget):
    def mouseReleaseEvent(self, event):
        self.m_drag = False
        self.position_to_top_right()
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.init_data()
        self.setup_timers()
        self.m_drag = False
        self.m_drag_position = QPoint()

    def init_ui(self):
        """初始化用户界面并固定在右上角底层"""
        # 关键修改：设置窗口标志为底层显示
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnBottomHint |
            Qt.Tool |
            Qt.X11BypassWindowManagerHint
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setFixedSize(400, 120)
        self.setWindowOpacity(0.85)

        # 主布局
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(1)
        main_layout.addStretch(0)

        # === 第一行布局 ===
        row1_layout = QHBoxLayout()
        row1_layout.setSpacing(1)

        # CPU标签（保持原样）
        self.lbl_cpu = self.create_fixed_label("CPU: --%", 150)
        row1_layout.addWidget(self.lbl_cpu, alignment=Qt.AlignLeft)  # 确保左对齐

        # GPU利用率标签
        self.lbl_gpu_usage = self.create_fixed_label("GPU: --%", 150)
        row1_layout.addWidget(self.lbl_gpu_usage, alignment=Qt.AlignLeft)  # 明确左对齐[2,6](@ref)

        # 上传网速标签
        self.lbl_upload = self.create_fixed_label("▲ --", 100, "#4FC3F7")
        row1_layout.addWidget(self.lbl_upload, alignment=Qt.AlignLeft)

        # === 第二行布局 ===
        row2_layout = QHBoxLayout()
        row2_layout.setSpacing(20)

        # 内存标签
        self.lbl_mem = self.create_fixed_label("RAM: --%", 150)
        row2_layout.addWidget(self.lbl_mem, alignment=Qt.AlignLeft)

        # GPU温度标签
        self.lbl_gpu_temp = self.create_fixed_label("GPU: --°C", 150)
        row2_layout.addWidget(self.lbl_gpu_temp, alignment=Qt.AlignLeft)  # 明确左对齐[2,6](@ref)

        # 下载网速标签
        self.lbl_download = self.create_fixed_label("▼ --", 100, "#81C784")
        row2_layout.addWidget(self.lbl_download, alignment=Qt.AlignLeft)

        # 添加到主布局
        main_layout.addLayout(row1_layout)
        main_layout.addLayout(row2_layout)
        self.setLayout(main_layout)

        # 固定在桌面右上角
        self.position_to_top_right()

    def position_to_top_right(self):
        """将窗口定位到屏幕右上角"""
        screen_geometry = QDesktopWidget().screenGeometry()
        screen_width = screen_geometry.width()

        margin = 10
        x_pos = screen_width - self.width() - margin
        y_pos = -78

        self.move(x_pos, y_pos)

    def create_fixed_label(self, text, width, color="white"):
        """创建固定宽度的标签"""
        label = QLabel(text)
        label.setFont(QFont("Arial", 12, QFont.Bold))
        label.setStyleSheet(f"color: {color};")
        label.setFixedWidth(width)
        label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        return label

    def init_data(self):
        """初始化数据采集变量"""
        self.last_sent = psutil.net_io_counters().bytes_sent
        self.last_recv = psutil.net_io_counters().bytes_recv
        self.last_time = time.time()

        self.gpu_available = False
        if GPUtil:
            try:
                if GPUtil.getGPUs():
                    self.gpu_available = True
            except:
                pass

    def setup_timers(self):
        """设置定时器"""
        self.sys_timer = QTimer()
        self.sys_timer.timeout.connect(self.update_system_info)
        self.sys_timer.start(1000)

    def get_network_speed(self):
        """计算当前网络速度（返回KB/s）"""
        current_sent = psutil.net_io_counters().bytes_sent
        current_recv = psutil.net_io_counters().bytes_recv
        current_time = time.time()

        dt = current_time - self.last_time
        if dt > 0:
            # 计算字节/秒后转换为KB/s
            upload = (current_sent - self.last_sent) / dt / 1024
            download = (current_recv - self.last_recv) / dt / 1024
        else:
            upload = download = 0

        self.last_sent = current_sent
        self.last_recv = current_recv
        self.last_time = current_time

        return upload, download

    def format_network_speed(self, speed_kb):
        """智能格式化网络速度（自动选择KB/MB/GB单位）[1,7](@ref)

        根据网络速度值自动选择合适的单位：
        - < 1024 KB/s: 显示为KB/s
        - 1024-1048576 KB/s: 转换为MB/s
        - > 1048576 KB/s: 转换为GB/s
        """
        if speed_kb < 1024:  # 小于1MB
            return f"{speed_kb:.1f} KB/s"
        elif speed_kb < 1024 * 1024:  # 小于1GB
            return f"{speed_kb / 1024:.1f} MB/s"
        else:  # 大于等于1GB
            return f"{speed_kb / (1024 * 1024):.1f} GB/s"

    def get_gpu_info(self):
        """获取GPU信息"""
        gpu_usage = "N/A"
        gpu_temp = "N/A"

        if self.gpu_available:
            try:
                gpus = GPUtil.getGPUs()
                if gpus:
                    gpu = gpus[0]
                    gpu_usage = f"{gpu.load * 100:.1f}"
                    gpu_temp = f"{gpu.temperature:.1f}"
            except:
                pass

        return gpu_usage, gpu_temp

    def update_system_info(self):
        """更新系统监控信息"""
        # CPU使用率
        cpu_percent = psutil.cpu_percent()
        self.lbl_cpu.setText(f"CPU: {cpu_percent:.1f}%")

        # 内存显示
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        self.lbl_mem.setText(f"RAM: {mem_percent:.1f}%")

        # 网络速度（使用智能格式化）[1,7](@ref)
        upload, download = self.get_network_speed()
        self.lbl_upload.setText(f"▲ {self.format_network_speed(upload)}")
        self.lbl_download.setText(f"▼ {self.format_network_speed(download)}")

        # GPU信息
        gpu_usage, gpu_temp = self.get_gpu_info()
        self.lbl_gpu_usage.setText(f"GPU: {gpu_usage}%")
        self.lbl_gpu_temp.setText(f"GPU: {gpu_temp}°C")

        self.update()

    def paintEvent(self, event):
        """绘制半透明圆角背景"""
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QColor(0, 0, 0, 0))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(self.rect(), 15, 15)

    def mousePressEvent(self, event):
        """允许拖动但松开后自动回到右上角"""
        if event.button() == Qt.LeftButton:
            self.m_drag = True
            self.m_drag_position = event.globalPos() - self.pos()
            event.accept()

    def mouseMoveEvent(self, event):
        if self.m_drag and event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self.m_drag_position)
            event.accept()

    def mouseReleaseEvent(self, event):
        self.m_drag = False
        self.position_to_top_right()

    def mouseDoubleClickEvent(self, event):
        """双击打开任务管理器"""
        import subprocess
        try:
            subprocess.Popen("taskmgr")  # 方式1：直接调用系统命令
        except Exception as e:

if __name__ == "__main__":
    app = QApplication(sys.argv)
    monitor = SystemMonitor()
    monitor.show()
    sys.exit(app.exec_())