import sys
import subprocess
import re
import ctypes
import pywifi
from pywifi import const
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QLabel, QRadioButton, QLineEdit, QPushButton, QGroupBox,
                               QMessageBox, QTextEdit, QScrollArea, QFrame)
from PySide6.QtCore import Qt, QProcess
from PySide6.QtGui import QFont, QPalette, QColor


class DNSManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.interface_name = ""
        self.init_ui()
        self.check_admin()
        self.get_network_info()

    def check_admin(self):
        """检查管理员权限"""
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.show_error("需要管理员权限", "请以管理员身份运行此程序")
                sys.exit(1)
        except:
            self.show_error("权限错误", "无法检查管理员权限")
            sys.exit(1)

    def get_network_info(self):
        """获取网络信息"""
        self.wifi_name = self.get_connected_wifi()
        self.interface_name = self.get_interface_name(self.wifi_name)
        self.current_ip, self.ip_status = self.get_current_ipv4()

        # 更新UI显示
        self.wifi_label.setText(f"当前WiFi: {self.wifi_name}")
        self.interface_label.setText(f"网络接口: {self.interface_name}")
        self.update_ipv4_display()

        # 根据IP自动选择模式
        if self.current_ip.startswith('192.168.'):
            self.auto_radio.setChecked(True)
        else:
            self.manual_radio.setChecked(True)
        self.on_mode_change()

    def get_connected_wifi(self):
        """获取当前连接的WiFi名称"""
        try:
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            if iface.status() == const.IFACE_CONNECTED:
                networks = iface.scan_results()
                for network in networks:
                    if network.ssid:
                        return network.ssid
            return "Unknown WiFi"
        except Exception as e:
            return f"Error: {str(e)}"

    def get_interface_name(self, wifi_name):
        """获取网络接口名称"""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            for line in result.stdout.split('\n'):
                if "名称" in line or "Name" in line:
                    return line.split(":")[1].strip()
            return wifi_name
        except Exception as e:
            return wifi_name

    def get_current_ipv4(self):
        """获取当前IPv4地址"""
        try:
            result = subprocess.run(
                ["ipconfig"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            for line in result.stdout.split('\n'):
                if "IPv4" in line or "IPV4" in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        if ip.startswith('192.168.'):
                            return ip, "192.168网段"
                        else:
                            return ip, "其他网段"
            return "未知", "无法获取"
        except Exception as e:
            return "错误", f"获取失败"

    def validate_dns(self, address):
        """验证DNS地址格式"""
        if not address:
            return True
        pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
        match = re.match(pattern, address)
        if not match:
            return False
        return all(0 <= int(part) <= 255 for part in match.groups())

    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("DNS智能设置工具")
        self.setFixedSize(500, 500)

        # 中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # 标题
        title_label = QLabel("DNS智能设置工具")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        layout.addWidget(title_label)

        # 网络信息
        info_group = QGroupBox("网络信息")
        info_layout = QVBoxLayout(info_group)

        self.wifi_label = QLabel("当前WiFi: 获取中...")
        self.interface_label = QLabel("网络接口: 获取中...")
        self.ip_label = QLabel("当前IPv4: 获取中...")

        info_layout.addWidget(self.wifi_label)
        info_layout.addWidget(self.interface_label)
        info_layout.addWidget(self.ip_label)

        layout.addWidget(info_group)

        # DNS模式选择
        mode_group = QGroupBox("DNS设置模式")
        mode_layout = QVBoxLayout(mode_group)

        self.auto_radio = QRadioButton("自动获取DNS")
        self.manual_radio = QRadioButton("手动设置DNS")

        self.auto_radio.toggled.connect(self.on_mode_change)

        mode_layout.addWidget(self.auto_radio)
        mode_layout.addWidget(self.manual_radio)

        layout.addWidget(mode_group)

        # 手动DNS设置
        self.manual_group = QGroupBox("手动DNS设置")
        manual_layout = QVBoxLayout(self.manual_group)

        # 首选DNS
        primary_layout = QHBoxLayout()
        primary_layout.addWidget(QLabel("首选DNS:"))
        self.primary_dns = QLineEdit()
        self.primary_dns.setPlaceholderText("例如: 8.8.8.8")
        primary_layout.addWidget(self.primary_dns)
        manual_layout.addLayout(primary_layout)

        # 备用DNS
        secondary_layout = QHBoxLayout()
        secondary_layout.addWidget(QLabel("备用DNS:"))
        self.secondary_dns = QLineEdit()
        self.secondary_dns.setPlaceholderText("例如: 8.8.4.4 (可选)")
        secondary_layout.addWidget(self.secondary_dns)
        manual_layout.addLayout(secondary_layout)

        layout.addWidget(self.manual_group)

        # 按钮区域
        button_layout = QHBoxLayout()

        self.apply_btn = QPushButton("应用设置")
        self.show_dns_btn = QPushButton("显示DNS")
        self.refresh_btn = QPushButton("刷新IP")
        self.quit_btn = QPushButton("退出")

        self.apply_btn.clicked.connect(self.apply_dns)
        self.show_dns_btn.clicked.connect(self.show_current_dns)
        self.refresh_btn.clicked.connect(self.refresh_network_info)
        self.quit_btn.clicked.connect(self.close)

        button_layout.addWidget(self.apply_btn)
        button_layout.addWidget(self.show_dns_btn)
        button_layout.addWidget(self.refresh_btn)
        button_layout.addWidget(self.quit_btn)

        layout.addLayout(button_layout)

    def on_mode_change(self):
        """模式切换"""
        if self.auto_radio.isChecked():
            self.primary_dns.setEnabled(False)
            self.secondary_dns.setEnabled(False)
        else:
            self.primary_dns.setEnabled(True)
            self.secondary_dns.setEnabled(True)
            self.set_smart_dns_defaults()

    def set_smart_dns_defaults(self):
        """设置智能DNS默认值"""
        # 只有在非192.168网段时才自动填充公共DNS
        if not self.current_ip.startswith('192.168.'):
            self.primary_dns.setText("8.8.8.8")
            self.secondary_dns.setText("8.8.4.4")
        else:
            # 192.168网段时清空输入框，让用户手动输入
            self.primary_dns.clear()
            self.secondary_dns.clear()

    def update_ipv4_display(self):
        """更新IP显示"""
        self.ip_label.setText(f"当前IPv4: {self.current_ip} ({self.ip_status})")
        if "192.168" in self.ip_status:
            self.ip_label.setStyleSheet("color: green;")
        elif "错误" in self.current_ip or "未知" in self.current_ip:
            self.ip_label.setStyleSheet("color: red;")
        else:
            self.ip_label.setStyleSheet("color: blue;")

    def refresh_network_info(self):
        """刷新网络信息"""
        self.current_ip, self.ip_status = self.get_current_ipv4()
        self.update_ipv4_display()

    def apply_dns(self):
        """应用DNS设置"""
        if self.auto_radio.isChecked():
            self.set_auto_dns()
        else:
            self.set_manual_dns()

    def set_auto_dns(self):
        """设置自动DNS"""
        try:
            result = subprocess.run(
                f'netsh interface ipv4 set dnsservers name="{self.interface_name}" source=dhcp',
                capture_output=True,
                text=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.returncode == 0:
                self.show_success("DNS已设置为自动获取模式")
            else:
                self.show_error("设置失败", f"自动获取DNS设置失败:\n{result.stderr}")
        except Exception as e:
            self.show_error("设置失败", f"自动获取DNS设置失败:\n{str(e)}")

    def set_manual_dns(self):
        """设置手动DNS"""
        primary = self.primary_dns.text().strip()
        secondary = self.secondary_dns.text().strip()

        # 验证输入
        errors = []
        if not primary:
            errors.append("首选DNS不能为空")
        elif not self.validate_dns(primary):
            errors.append("首选DNS格式无效")

        if secondary and not self.validate_dns(secondary):
            errors.append("备用DNS格式无效")

        if errors:
            self.show_error("输入错误", "\n".join(errors))
            return

        try:
            # 清除现有设置
            subprocess.run(
                f'netsh interface ipv4 set dnsservers name="{self.interface_name}" source=dhcp',
                capture_output=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # 设置首选DNS
            result1 = subprocess.run(
                f'netsh interface ipv4 set dnsservers name="{self.interface_name}" static {primary} primary',
                capture_output=True,
                text=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # 设置备用DNS
            if secondary:
                result2 = subprocess.run(
                    f'netsh interface ipv4 add dnsservers name="{self.interface_name}" {secondary} index=2',
                    capture_output=True,
                    text=True,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

            if result1.returncode == 0:
                self.show_success(
                    f"DNS设置已更新\n\n"
                    f"首选DNS: {primary}\n"
                    f"备用DNS: {secondary or '无'}\n\n"
                    f"接口: {self.interface_name}"
                )
                self.show_current_dns()
            else:
                self.show_error("设置失败", f"DNS设置失败:\n{result1.stderr}")

        except Exception as e:
            self.show_error("设置失败", f"DNS设置失败:\n{str(e)}")

    def show_current_dns(self):
        """显示当前DNS配置"""
        try:
            dns_info = self.get_current_dns_info()

            # 创建新窗口
            self.dns_window = QMainWindow()
            self.dns_window.setWindowTitle("当前DNS配置信息")
            self.dns_window.setFixedSize(700, 550)

            central = QWidget()
            self.dns_window.setCentralWidget(central)
            layout = QVBoxLayout(central)

            # 标题
            title = QLabel("DNS配置详情")
            title.setAlignment(Qt.AlignCenter)
            title.setFont(QFont("Arial", 14, QFont.Bold))
            layout.addWidget(title)

            # 文本区域
            text_edit = QTextEdit()
            text_edit.setPlainText(dns_info)
            text_edit.setReadOnly(True)
            text_edit.setFont(QFont("Consolas", 10))
            layout.addWidget(text_edit)

            # 按钮
            btn_layout = QHBoxLayout()
            refresh_btn = QPushButton("刷新")
            copy_btn = QPushButton("复制文本")
            close_btn = QPushButton("关闭")

            refresh_btn.clicked.connect(lambda: self.refresh_dns_info(text_edit))
            copy_btn.clicked.connect(lambda: self.copy_to_clipboard(dns_info))
            close_btn.clicked.connect(self.dns_window.close)

            btn_layout.addWidget(refresh_btn)
            btn_layout.addWidget(copy_btn)
            btn_layout.addWidget(close_btn)

            layout.addLayout(btn_layout)

            self.dns_window.show()

        except Exception as e:
            self.show_error("错误", f"无法显示DNS信息: {str(e)}")

    def get_current_dns_info(self):
        """获取当前DNS信息"""
        try:
            ipconfig_result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            netsh_result = subprocess.run(
                f'netsh interface ipv4 show dnsservers name="{self.interface_name}"',
                capture_output=True,
                text=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            info = "当前DNS配置信息\n"
            info += "=" * 50 + "\n\n"
            info += f"接口名称: {self.interface_name}\n\n"
            info += "DNS服务器配置:\n"

            # 解析DNS信息
            dns_servers = []
            for line in ipconfig_result.stdout.split('\n'):
                if "DNS Servers" in line or "DNS 服务器" in line:
                    dns_servers.append(line.strip())
                elif line.strip() and re.match(r'^\d+\.\d+\.\d+\.\d+', line.strip()):
                    if dns_servers:  # 只在DNS部分添加IP
                        dns_servers.append(line.strip())

            if dns_servers:
                for i, server in enumerate(dns_servers, 1):
                    info += f"   DNS服务器 {i}: {server}\n"
            else:
                info += "   未找到DNS服务器信息\n"

            info += f"\nnetsh接口配置:\n"
            info += netsh_result.stdout if netsh_result.stdout else "   无法获取接口DNS配置\n"

            return info

        except Exception as e:
            return f"获取DNS信息时出错: {str(e)}"

    def refresh_dns_info(self, text_edit):
        """刷新DNS信息"""
        dns_info = self.get_current_dns_info()
        text_edit.setPlainText(dns_info)

    def copy_to_clipboard(self, text):
        """复制到剪贴板"""
        QApplication.clipboard().setText(text)
        self.show_success("文本已复制到剪贴板")

    def show_success(self, message):
        """显示成功消息"""
        QMessageBox.information(self, "成功", message)

    def show_error(self, title, message):
        """显示错误消息"""
        QMessageBox.critical(self, title, message)


def main():
    # 检查管理员权限
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            # 请求管理员权限
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
    except:
        pass

    app = QApplication(sys.argv)
    window = DNSManager()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
