import tkinter as tk
from tkinter import messagebox, ttk
import subprocess
import re
import pywifi
from pywifi import const
import os
import sys
import ctypes


def is_admin():
    """检查是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def get_connected_wifi():
    """获取当前连接的WiFi名称（带错误处理）"""
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
        print(f"WiFi获取错误: {str(e)}")
        return "Error: WiFi Unavailable"


def get_interface_name(wifi_name):
    """根据WiFi名称获取对应的网络接口名称"""
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        # 解析接口名称
        for line in result.stdout.split('\n'):
            if "名称" in line or "Name" in line:
                return line.split(":")[1].strip()
        return wifi_name  # 回退使用WiFi名称
    except Exception as e:
        print(f"接口获取错误: {str(e)}")
        return wifi_name


def validate_dns(address):
    """验证DNS地址格式"""
    if not address:  # 允许空字符串（备用DNS可以为空）
        return True

    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, address)
    if not match:
        return False

    # 验证每个数字在0-255之间
    return all(0 <= int(part) <= 255 for part in match.groups())


def apply_dns():
    """应用DNS设置"""
    interface = interface_name

    if auto_dns_var.get():  # 自动获取DNS
        try:
            subprocess.run(
                f'netsh interface ipv4 set dnsservers name="{interface}" source=dhcp',
                check=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            messagebox.showinfo("成功", "DNS已设置为自动获取")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("错误", f"设置失败: {str(e)}")
    else:  # 手动设置DNS
        primary = entry_primary.get().strip()
        secondary = entry_secondary.get().strip()

        # 验证输入
        errors = []
        if not primary:
            errors.append("首选DNS不能为空")
        elif not validate_dns(primary):
            errors.append("首选DNS格式无效")

        if secondary and not validate_dns(secondary):
            errors.append("备用DNS格式无效")

        if errors:
            messagebox.showerror("输入错误", "\n".join(errors))
            return

        try:
            # 清除现有DNS设置
            subprocess.run(
                f'netsh interface ipv4 set dnsservers name="{interface}" source=dhcp',
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # 设置首选DNS
            subprocess.run(
                f'netsh interface ipv4 set dnsservers name="{interface}" static {primary} primary',
                check=True,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            # 设置备用DNS
            if secondary:
                subprocess.run(
                    f'netsh interface ipv4 add dnsservers name="{interface}" {secondary} index=2',
                    check=True,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

            messagebox.showinfo("成功", f"DNS设置已更新\n首选: {primary}\n备用: {secondary or '无'}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("错误", f"设置失败: {str(e)}")

    # 显示当前DNS
    show_current_dns(interface)


def show_current_dns(interface):
    """在CMD中显示当前DNS配置"""
    try:
        # 创建临时批处理文件
        bat_content = f"""@echo off
ipconfig /all | findstr /C:"DNS Servers"
echo.
echo [IPv4 DNS配置]
netsh interface ipv4 show dnsservers name="{interface}"
echo.
pause
"""
        with open("show_dns.bat", "w") as f:
            f.write(bat_content)

        # 执行批处理文件
        subprocess.Popen(
            ["cmd", "/c", "start", "show_dns.bat"],
            shell=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except Exception as e:
        messagebox.showerror("错误", f"无法显示DNS信息: {str(e)}")


def on_mode_change():
    """切换DNS设置模式时的回调"""
    if auto_dns_var.get():
        entry_primary.config(state='disabled')
        entry_secondary.config(state='disabled')
    else:
        entry_primary.config(state='normal')
        entry_secondary.config(state='normal')


def main():
    global interface_name, auto_dns_var, entry_primary, entry_secondary

    # 检查管理员权限
    if not is_admin():
        # 请求管理员权限
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)

    # 获取网络信息
    wifi_name = get_connected_wifi()
    interface_name = get_interface_name(wifi_name)  # 使用WiFi名称获取接口

    # 创建主窗口
    root = tk.Tk()
    root.title("DNS设置工具")
    root.geometry("420x350")
    root.resizable(False, False)

    # 主框架
    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    # 显示WiFi信息
    ttk.Label(main_frame, text=f"当前WiFi: {wifi_name}", font=("Arial", 10)).pack(pady=(0, 5))
    ttk.Label(main_frame, text=f"网络接口: {interface_name}", font=("Arial", 9)).pack(pady=(0, 15))

    # DNS设置模式选择
    mode_frame = ttk.LabelFrame(main_frame, text="DNS设置模式")
    mode_frame.pack(fill=tk.X, pady=5)

    auto_dns_var = tk.BooleanVar(value=True)

    ttk.Radiobutton(
        mode_frame,
        text="自动获取DNS",
        variable=auto_dns_var,
        value=True,
        command=on_mode_change
    ).grid(row=0, column=0, sticky='w', padx=10, pady=5)

    ttk.Radiobutton(
        mode_frame,
        text="手动设置DNS",
        variable=auto_dns_var,
        value=False,
        command=on_mode_change
    ).grid(row=1, column=0, sticky='w', padx=10, pady=5)

    # 手动设置区域
    manual_frame = ttk.LabelFrame(main_frame, text="手动DNS设置")
    manual_frame.pack(fill=tk.X, pady=10)

    ttk.Label(manual_frame, text="首选DNS:").grid(row=0, column=0, padx=5, pady=5, sticky='e')
    entry_primary = ttk.Entry(manual_frame, width=18)
    entry_primary.grid(row=0, column=1, padx=5, pady=5, sticky='w')
    entry_primary.insert(0, "8.8.8.8")

    ttk.Label(manual_frame, text="备用DNS:").grid(row=1, column=0, padx=5, pady=5, sticky='e')
    entry_secondary = ttk.Entry(manual_frame, width=18)
    entry_secondary.grid(row=1, column=1, padx=5, pady=5, sticky='w')
    entry_secondary.insert(0, "8.8.4.4")

    # 初始禁用手动输入
    on_mode_change()

    # 按钮框架
    btn_frame = ttk.Frame(main_frame)
    btn_frame.pack(pady=15)

    ttk.Button(btn_frame, text="应用设置", command=apply_dns).pack(side=tk.LEFT, padx=10)
    ttk.Button(btn_frame, text="显示当前DNS", command=lambda: show_current_dns(interface_name)).pack(side=tk.LEFT,
                                                                                                     padx=10)

    # 运行主循环
    root.mainloop()


if __name__ == "__main__":
    main()