import http.client

SERVER_ADDR = "192.168.179.129"  # 防火墙外网IP
SERVER_PORT = 8080
CLIENT_ADDR = "192.168.179.1"  # 防火墙外网的网关，它想访问内网的Web
CLIENT_PORT = 6666

connect = http.client.HTTPConnection(
    SERVER_ADDR, SERVER_PORT, source_address=(CLIENT_ADDR, CLIENT_PORT))

connect.request("GET", "/")
