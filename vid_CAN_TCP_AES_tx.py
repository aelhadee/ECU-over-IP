import datetime

import cv2
import socket
import struct
import time
from random import randrange
from Crypto.Cipher import AES  # pip3 install pycryptodome
import imutils

host = '192.168.1.10'
# host = '10.42.0.1'
# host = '192.168.137.110'
port = 9990
address = (host, port)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
vid_obj = cv2.VideoCapture(0)
msgs_matrix = []
secret_key = b'\x95S)\x93\x93)\xa0\xae\xf8\x9fuY\xec\xec\xdf\xd4]<\xb2\x00Y\xcdr}\x17U/\x1e\xb1\xe62\xac'
iv = b'\xa7S\x94{\x8c\xdf\x81E\xc5i}j\xa8\r~'
time_sent = []
user_log_name = "AES_OCB_TX_AX_Router_5GHz"
while True:
    ret, frame = vid_obj.read()
    # frame = imutils.resize(frame0, width=400)

    e, tx_img = cv2.imencode(".jpg", frame)  # encoding each frame into an image
    # e, tx_img = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY,80])  # encoding each frame into an image

    img_bytes = tx_img.tobytes()  # you can also try pickle.
    len_img = len(img_bytes)

    len_img_bytes = struct.pack("Q", len_img)  # Network, big-e, was 2 bytes, changed to 8 bytes to accommodate bigger
    # frames

    for i in range(400):  # generate 400 values to convert to bytes --> to simulate fresh CAN data
        msgs_matrix.append(randrange(256))

    msgs_matrix_bytes = bytes(msgs_matrix)
    aes_obj = AES.new(secret_key, AES.MODE_OCB, iv)
    [encrypted_payload, tag] = aes_obj.encrypt_and_digest(img_bytes + msgs_matrix_bytes)  # the jpg frame + CAN bytes
    # jpg image length is not encrypted because it's needed at the RX side since the jpg size is always different
    try:

        s.sendall(len_img_bytes + encrypted_payload + tag)  # length of the jpg + the frame itself + the 200 bytes
        t = datetime.datetime.now()
        time_sent.append(str(t.strftime("%I:%M:%S:%f %p")))
    except:
        lognamefile_data_sent = user_log_name + "_" + "tcp_packet_tx_" + str(time.time_ns()) + ".txt"
        with open(lognamefile_data_sent, "a") as log1:
            log1.write( "TX Clock time" + "\n")
            e = 0
            for i in range(int(len(time_sent))):
                log1.write(str(time_sent[e]) + "\n")
                e += 1
                if e >= int(len(time_sent)):
                    break


            log1.close()
        break


    # of CAN data
    msgs_matrix = []  # to avoid appending old data
    time.sleep(20 / 1000)

    print(time.time())
    if cv2.waitKey(1) == ord('x'):
        break

vid_obj.release()
cv2.destroyAllWindows()
