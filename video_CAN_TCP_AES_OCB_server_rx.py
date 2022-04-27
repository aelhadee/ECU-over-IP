import datetime
import socket
import time
import cv2
import struct
import numpy as np
from Crypto.Cipher import AES
import can
from can import Message
from PCANBasic import *  # for CAN channels using PeakCAN, USB1 and USB2
import matplotlib.pyplot as plt
import os
# from ping3 import ping
import pandas as pd

host = '192.168.1.10'
# host = '192.168.137.110'
# host = '10.42.0.1'
port = 9990
# tx_ip = '192.168.1.199'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65000)
s.bind((host, port))
s.listen()
conn, addr = s.accept()
# conn.setblocking(True)

secret_key = b'\x95S)\x93\x93)\xa0\xae\xf8\x9fuY\xec\xec\xdf\xd4]<\xb2\x00Y\xcdr}\x17U/\x1e\xb1\xe62\xac'
iv = b'\xa7S\x94{\x8c\xdf\x81E\xc5i}j\xa8\r~'

img_size = struct.calcsize("Q")  # 8-bytes since 2-bytes was causing an issue
data = b""
CAN_bytes = b""
f_n = 1
fps = []
mbps = []
MBps = 0
start_time_fps_mbps = time.time()
dt_count = 0
tcp_frame_number = 0
start_time_data_received = time.time()
start_time_data_auth = 0
dt_data_received = []
t_data_auth = []
user_log_name = "AES_OCB_RX_AX_router_5GHz"
#
# # CANFD BUS - 8 Mbits/s
# bus_FD = can.interface.Bus(bustype='pcan', channel='PCAN_USBBUS1', fd=True, f_clock=80000000, nom_brp=10, nom_tseg1=5,
#                            nom_tseg2=2, nom_sjw=1, data_brp=4, data_tseg1=7, data_tseg2=2, data_sjw=1)
# # Define CAN FD Messages:
# msg1 = Message(arbitration_id=0xE0, bitrate_switch=False, channel=PCAN_USBBUS1, dlc=64,
#                is_extended_id=False, is_fd=True, data=[0] * 64)  # start with all 0s, 64 bytes CAN payload
# msg1_tx = bus_FD.send_periodic(msg1, 0.05)  # transmit every 50 milliseconds
# # -----------------------------------------------------------------------------------
# #  FD Message 2
# msg2 = Message(arbitration_id=0xC1, bitrate_switch=False, channel=PCAN_USBBUS1, dlc=64,
#                is_extended_id=False, is_fd=True, data=[0] * 64)
# msg2_tx = bus_FD.send_periodic(msg2, 0.05)
# # -----------------------------------------------------------------------------------
# #   FD MESSAGE 3
# msg3 = Message(arbitration_id=0xF2, bitrate_switch=False, channel=PCAN_USBBUS1, dlc=64,
#                is_extended_id=False, is_fd=True, data=[0] * 64)
# msg3_tx = bus_FD.send_periodic(msg3, 0.05)
# # -----------------------------------------------------------------------------------
# msg4 = Message(arbitration_id=0xA0, bitrate_switch=False, channel=PCAN_USBBUS1, dlc=64,
#                is_extended_id=False, is_fd=True, data=[0] * 64)
# msg4_tx = bus_FD.send_periodic(msg4, 0.1)  # 100 ms
# # -----------------------------------------------------------------------------------
# msg5 = Message(arbitration_id=0xD5, bitrate_switch=False, channel=PCAN_USBBUS1, dlc=64,
#                is_extended_id=False, is_fd=True, data=[0] * 64)
# msg5_tx = bus_FD.send_periodic(msg5, 0.3)  # 300 ms
# # ====================================================================================
# # CAN BUS
# bus = can.interface.Bus(bustype='pcan', channel='PCAN_USBBUS2', fd=False, bitrate=500000)
# # MESSAGE 6 - CAN MESSAGE 1 (500K)
# msg6 = Message(arbitration_id=0xC5, bitrate_switch=False, channel=PCAN_USBBUS2, dlc=8,
#                is_extended_id=False, is_fd=False, data=[0] * 8)
# msg6_tx = bus.send_periodic(msg6, 0.05)  # 50 ms
# # -----------------------------------------------------------------------------------
#
# msg7 = Message(arbitration_id=0xF0, bitrate_switch=False, channel=PCAN_USBBUS2, dlc=8,
#                is_extended_id=False, is_fd=False, data=[0] * 8)
# msg7_tx = bus.send_periodic(msg7, 0.05)  # 50 ms
# # -----------------------------------------------------------------------------------
#
# msg8 = Message(arbitration_id=0xF1, bitrate_switch=False, channel=PCAN_USBBUS2, dlc=8,
#                is_extended_id=False, is_fd=False, data=[0] * 8)
# msg8_tx = bus.send_periodic(msg8, 0.05)  # 50 ms
# # -----------------------------------------------------------------------------------
#
# msg9 = Message(arbitration_id=0xF5, bitrate_switch=False, channel=PCAN_USBBUS2, dlc=8,
#                is_extended_id=False, is_fd=False, data=[0] * 8)
# msg9_tx = bus.send_periodic(msg9, 0.02)  # 20 ms
# # -----------------------------------------------------------------------------------
# msg10 = Message(arbitration_id=0xF10, bitrate_switch=False, channel=PCAN_USBBUS2, dlc=8,
#                 is_extended_id=False, is_fd=False, data=[0] * 8)
# msg10_tx = bus.send_periodic(msg10, 0.03)  # 30 ms

# # # video file info
# vid_name = "video" + str(time.time_ns()) + ".mp4"
# fourcc = cv2.VideoWriter_fourcc(*'mp4v')
# vid_out = cv2.VideoWriter(vid_name, fourcc, 20, (640, 480))
while True:
    # len of the frame image only
    while len(data) < img_size:
        rx_data = conn.recv(8 * 1024)
        data += rx_data

    recvd_img_len = data[:img_size]  # 0:2
    # frame
    data = data[img_size:]

    recvd_img_len_str = struct.unpack("Q", recvd_img_len)
    recvd_img_len_int = int(recvd_img_len_str[0])

    while len(data) < (recvd_img_len_int + 400 + 16):  # received frame length + CAN bytes + tag
        data += conn.recv(8 * 1024)

    # get the encrypted data of the frame and CAN payload
    rx_img = data[:recvd_img_len_int]
    CAN_bytes = data[recvd_img_len_int:(recvd_img_len_int + 400)]
    tag = data[recvd_img_len_int + 400:recvd_img_len_int + 400 + 16]
    aes_obj = AES.new(secret_key, AES.MODE_OCB, iv)
    #
    # """ Data Received log"""
    t = datetime.datetime.now()
    dt_data_received.append((time.time() - start_time_data_received) * 1000)
    dt_data_received.append((t.strftime("%I:%M:%S:%f %p")))
    start_time_data_received = time.time()

    try:
        start_time_data_auth = time.time()
        decrypted_msgs_matrix = aes_obj.decrypt_and_verify(rx_img + CAN_bytes, tag)
        # print('Decryption successful and msg is authentic')

        # How long does decryption and authentication take?
        t_data_auth.append((time.time() - start_time_data_auth) * 1000)  # ms

        # getting the actual bytes after decryption
        rx_img = decrypted_msgs_matrix[:recvd_img_len_int]
        CAN_bytes = decrypted_msgs_matrix[recvd_img_len_int:(recvd_img_len_int + 400)]



    except:
        print('Not authentic or the received data is incomplete ')

    data = data[recvd_img_len_int + 400 + 16:]  # store the bytes of the next new payload

    rx_img_int = np.frombuffer(bytes(rx_img), dtype=np.uint8)
    frame_final = cv2.imdecode(rx_img_int, cv2.IMREAD_COLOR)
    # cv2.imshow("Received video", frame_final)
    # vid_out.write(frame_final)
    if cv2.waitKey(1) == ord('q'):
        break

    # write the logs of Delta time between "Data received" and "Data Decrypted"
    tcp_frame_number += 1
    max_frames = 10 * 1000  # stop at max and write the log
    if tcp_frame_number >= max_frames:
        print(dt_data_received)

        logfilename_tcp_rx = user_log_name + "_" + "tcp_packet_rx_" + str(time.time_ns()) + ".txt"
        logfilename_tcp_decrypt = user_log_name + "_" + "tcp_packet_dcrpt_" + str(time.time_ns()) + ".txt"
        logfilename_fps_mbps = user_log_name + "_" + "fps_mbps_" + str(time.time_ns()) + ".txt"

        with open(logfilename_tcp_rx, "a") as log1:
            log1.write("RX_Delta_time" + "," + "Clock time" + "\n")

            y = 3
            e = 2
            for i in range(int(len(dt_data_received) / 2)):
                log1.write(str(dt_data_received[e]) + "," + str(dt_data_received[y]) + "\n")
                y += 2
                e += 2
                if e >= int(len(dt_data_received)):
                    break
            log1.close()
        # decryption and authentication time
        with open(logfilename_tcp_decrypt, "a") as log2:
            log2.write("Decrypt_auth_time" + "\n")
            e = 2
            for i in range(int(len(t_data_auth))):
                log2.write(str(t_data_auth[e]) + "," + "\n")
                e += 1
                if e >= int(len(t_data_auth)):
                    break
            log2.close()

            # Calculate FPS and Mbps
    f_n += 1
    MBps += (len(recvd_img_len + rx_img + CAN_bytes + tag + data)) / (1000 * 1000)
    # print(len(rx_img))
    mbps1 = (MBps * 8)

    # -----------------------------
    if time.time() - start_time_fps_mbps >= 1:
        # Frame
        fps1 = f_n
        start_time_fps_mbps = time.time()

        print("%.2f FPS     %.2f Mbps" % (fps1, mbps1))

        fps.append(fps1)
        mbps.append(mbps1)

        f_n = 0
        MBps = 0

    if tcp_frame_number >= max_frames:
        with open(logfilename_fps_mbps, "a") as log3:
            log3.write("FPS" + "," + "Mbps" + "\n")
            e = 1
            for i in range(int(len(fps))):
                log3.write(str(fps[e]) + "," + str(mbps[e]) + "\n")
                e += 1
                if e >= int(len(fps)):
                    break
            log3.close()

        print("Done")
        cv2.destroyAllWindows()
        conn.close()
        s.close()
        break

    frame_final = []
    rx_img_int = []
    recvd_img_len = b""
    rx_img = []
    rx_data = b""
    # ---------------------send CAN data-------------------------------
    # resetting CAN payload to get the new data from the received TCP packet
    msg1_data = []
    msg2_data = []
    msg3_data = []
    msg4_data = []
    msg5_data = []
    msg6_data = []
    msg7_data = []
    msg8_data = []
    msg9_data = []
    msg10_data = []

    #   Get the new CAN bytes that just arrived
    # CAN FD MSG 1
    # for e in range(3, 67):
    #     msg1_data.append((CAN_bytes[e]))
    # msg1.data = msg1_data
    #
    # # CAN FD MSG 2
    # for e in range(72, 136):
    #     msg2_data.append((CAN_bytes[e]))
    # msg2.data = msg2_data
    #
    # # CAN FD MSG 3
    # for e in range(141, 205):
    #     msg3_data.append((CAN_bytes[e]))
    # msg3.data = msg3_data
    #
    # # CAN FD MSG 4
    # for e in range(210, 274):
    #     msg4_data.append((CAN_bytes[e]))
    # msg4.data = msg4_data
    #
    # # CAN FD MSG 5
    # for e in range(279, 343):
    #     msg5_data.append((CAN_bytes[e]))
    # msg5.data = msg5_data
    #
    # # CAN MSG 1 - MESSAGE 6
    # for e in range(346, 354):
    #     msg6_data.append((CAN_bytes[e]))
    # msg6.data = msg6_data
    #
    # # CAN MSG 2 - MESSAGE 7
    # for e in range(357, 365):
    #     msg7_data.append((CAN_bytes[e]))
    # msg7.data = msg7_data
    #
    # # CAN MSG 3 - MESSAGE 8
    # for e in range(368, 376):
    #     msg8_data.append((CAN_bytes[e]))
    # msg8.data = msg8_data
    #
    # # CAN MSG 4 - MESSAGE 9
    # for e in range(379, 387):
    #     msg9_data.append((CAN_bytes[e]))
    # msg9.data = msg9_data
    #
    # # CAN MSG 5 - MESSAGE 10
    # for e in range(390, 398):
    #     msg10_data.append((CAN_bytes[e]))
    # msg10.data = msg10_data

    time.sleep(10 / 1000)

dt_data_rx_plt = []
e = 2
# gettin dt time to plot
for i in range(int(len(dt_data_received) / 2)):
    dt_data_rx_plt.append(dt_data_received[e])
    e += 2
    if e >= len(dt_data_received):
        break

# Getting the number of TCP frames:
tcp_frames_plt = list(range(1, max_frames))

# TCP Frames delta time
plt.subplot(1,2,1)
plt.scatter(tcp_frames_plt,dt_data_rx_plt)
plt.xlabel('TCP frame number')
plt.ylabel('Delta time (in ms) between each received TCP frame (AES OCB)')

plt.subplot(1,2,2)
plt.boxplot(dt_data_rx_plt)
plt.ylabel("Delta time (in ms) between each received TCP frame (AES OCB)")
plt.show()

dt_data_rx_plt_pd = pd.DataFrame(dt_data_rx_plt)
print(dt_data_rx_plt_pd.describe())
t_data_auth_pd = pd.DataFrame(t_data_auth)
print(t_data_auth_pd.describe())

# Decryption time
plt.subplot(1,2,1)
plt.scatter(tcp_frames_plt, t_data_auth[1:])
plt.xlabel('TCP frame number')
plt.ylabel('AES_OCB Decryption and Authentication time (in ms)')
# Box plot
plt.subplot(1,2,2)
plt.boxplot(t_data_auth)
plt.ylabel("AES_OCB Decryption and Authentication time (in ms)")
plt.show()


# FPS & Mbps - # 2 lines
plt.subplot(2,1,1)
plt.plot(fps[1:], color="blue", label="Frames Per Second")
plt.xlabel("Seconds")
plt.ylabel("FPS")
plt.legend()
plt.subplot(2,1,2)
plt.plot(mbps[1:], color="red", label="Bitrate")
plt.xlabel("Seconds")
plt.ylabel("Mbps")
plt.legend()
plt.show()

