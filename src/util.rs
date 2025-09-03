pub fn std_to_glommio_socket(std_socket: std::net::UdpSocket) -> glommio::net::UdpSocket {
    let socket2 = socket2::Socket::from(std_socket);
    glommio::net::UdpSocket::from(socket2)
}
