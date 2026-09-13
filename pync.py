#!/usr/bin/env python3
"""A minimal netcat-like TCP/UDP sender, listener, and file transfer tool."""

import argparse
import os
from pathlib import Path
import socket
import struct
import sys
import uuid


FILE_MAGIC = b"PYNCF001"
REQUEST_MAGIC = b"PYNCGET1"
FILE_HEADER = struct.Struct("!8s16sIIH")
FRAME_LENGTH = struct.Struct("!I")
NAME_LENGTH = struct.Struct("!H")
CHUNK_SIZE = 60_000
MAX_FRAME_SIZE = 65_535


def port_number(value: str) -> int:
    """Parse and validate a TCP/UDP port number."""
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send or listen over TCP/UDP (minimal nc-compatible mode)."
    )
    parser.add_argument("-u", action="store_true", help="use UDP instead of TCP")
    parser.add_argument("-l", action="store_true", help="listen mode")
    parser.add_argument("-p", type=port_number, metavar="PORT", help="local port")
    parser.add_argument(
        "-server", "--server", action="store_true", help="serve requested files"
    )
    parser.add_argument(
        "-upload", "--upload", type=Path, metavar="FILE", help="send a file"
    )
    parser.add_argument(
        "-receive",
        "--receive",
        type=Path,
        metavar="DIRECTORY",
        help="receive files into a directory (listen mode only)",
    )
    parser.add_argument(
        "-download",
        "--download",
        metavar="FILENAME",
        help="request and download a file from a server",
    )
    parser.add_argument("address", nargs="?", help="destination address")
    parser.add_argument("port", nargs="?", type=port_number, help="destination port")

    args = parser.parse_args()
    if args.l:
        if args.p is None:
            parser.error("listen mode requires -p PORT")
        if args.address is not None or args.port is not None:
            parser.error("listen mode does not accept a destination")
        if args.upload is not None:
            parser.error("-upload cannot be used in listen mode")
        if args.download is not None:
            parser.error("-download cannot be used in listen mode")
        if args.server and args.receive is not None:
            parser.error("-server cannot be used with -receive")
        if args.server and args.u:
            parser.error("-server currently supports TCP only")
    else:
        if args.p is not None:
            parser.error("-p can only be used with -l")
        if args.address is None or args.port is None:
            parser.error("send mode requires ADDRESS and PORT")
        if args.receive is not None:
            parser.error("-receive can only be used with -l")
        if args.server:
            parser.error("-server can only be used with -l")
        if args.upload is not None and args.download is not None:
            parser.error("-upload and -download cannot be used together")
        if args.download is not None and args.u:
            parser.error("-download currently supports TCP only")
        if args.upload is not None and not args.upload.is_file():
            parser.error(f"upload file does not exist: {args.upload}")
    return args


def unique_destination(directory: Path, filename: str) -> Path:
    """Choose a destination without overwriting an existing file."""
    safe_name = Path(filename).name
    if not safe_name or safe_name in {".", ".."}:
        raise ValueError("invalid file name")

    candidate = directory / safe_name
    if not candidate.exists():
        return candidate

    stem = Path(safe_name).stem
    suffix = Path(safe_name).suffix
    number = 1
    while True:
        candidate = directory / f"{stem} ({number}){suffix}"
        if not candidate.exists():
            return candidate
        number += 1


class FileReceiver:
    """Collect file chunks and save a file once every chunk has arrived."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.transfers: dict[bytes, dict[str, object]] = {}
        self.completed = 0

    def receive(self, packet: bytes) -> None:
        if len(packet) < FILE_HEADER.size:
            raise ValueError("file packet is too short")

        magic, transfer_id, index, total, name_length = FILE_HEADER.unpack_from(packet)
        if magic != FILE_MAGIC:
            raise ValueError("invalid file packet")
        if total == 0 or index >= total:
            raise ValueError("invalid file chunk number")
        name_end = FILE_HEADER.size + name_length
        if name_length == 0 or name_end > len(packet):
            raise ValueError("invalid file name")

        filename = packet[FILE_HEADER.size:name_end].decode("utf-8")
        chunk = packet[name_end:]
        transfer = self.transfers.setdefault(
            transfer_id, {"filename": filename, "total": total, "chunks": {}}
        )
        if transfer["filename"] != filename or transfer["total"] != total:
            raise ValueError("inconsistent file transfer metadata")

        chunks = transfer["chunks"]
        assert isinstance(chunks, dict)
        chunks[index] = chunk
        if len(chunks) != total:
            return

        destination = unique_destination(self.directory, filename)
        temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.part")
        try:
            with temporary.open("wb") as output:
                for chunk_index in range(total):
                    output.write(chunks[chunk_index])
            os.replace(temporary, destination)
        finally:
            if temporary.exists():
                temporary.unlink()

        del self.transfers[transfer_id]
        self.completed += 1
        print(f"pync: received {destination}", file=sys.stderr)


def file_packets(path: Path):
    """Yield encoded chunks for one file transfer."""
    filename = path.name.encode("utf-8")
    if len(filename) > 65535:
        raise ValueError("file name is too long")

    size = path.stat().st_size
    total = max(1, (size + CHUNK_SIZE - 1) // CHUNK_SIZE)
    transfer_id = uuid.uuid4().bytes
    with path.open("rb") as source:
        for index in range(total):
            chunk = source.read(CHUNK_SIZE)
            yield FILE_HEADER.pack(
                FILE_MAGIC, transfer_id, index, total, len(filename)
            ) + filename + chunk


def send_file_tcp(connection: socket.socket, path: Path) -> None:
    for packet in file_packets(path):
        connection.sendall(FRAME_LENGTH.pack(len(packet)) + packet)


def output_data(data: bytes) -> None:
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def listen_udp(port: int, receive: Path | None) -> None:
    receiver = FileReceiver(receive) if receive else None
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("0.0.0.0", port))
        listener.settimeout(0.2)
        while True:
            try:
                data, _address = listener.recvfrom(MAX_FRAME_SIZE)
            except socket.timeout:
                continue
            if receiver:
                receiver.receive(data)
            else:
                output_data(data)


def receive_exact(connection: socket.socket, size: int) -> bytes | None:
    data = bytearray()
    while len(data) < size:
        try:
            part = connection.recv(size - len(data))
        except socket.timeout:
            continue
        if not part:
            return None
        data.extend(part)
    return bytes(data)


def receive_file_tcp(connection: socket.socket, directory: Path) -> None:
    receiver = FileReceiver(directory)
    while True:
        length_data = receive_exact(connection, FRAME_LENGTH.size)
        if length_data is None:
            break
        frame_size = FRAME_LENGTH.unpack(length_data)[0]
        if not FILE_HEADER.size <= frame_size <= MAX_FRAME_SIZE:
            raise ValueError("invalid file frame size")
        packet = receive_exact(connection, frame_size)
        if packet is None:
            raise ValueError("incomplete file frame")
        receiver.receive(packet)
    if receiver.completed != 1:
        raise ValueError("file transfer ended before the file was complete")


def requested_file(filename: str) -> Path:
    if not filename or Path(filename).name != filename or "/" in filename or "\\" in filename:
        raise ValueError("only a file name in the server's current directory is allowed")
    path = Path.cwd() / filename
    if not path.is_file():
        raise FileNotFoundError(f"file not found: {filename}")
    return path


def serve_tcp(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen()
        listener.settimeout(0.2)

        while True:
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue

            with connection:
                connection.settimeout(0.2)
                try:
                    magic = receive_exact(connection, len(REQUEST_MAGIC))
                    length_data = receive_exact(connection, NAME_LENGTH.size)
                    if magic != REQUEST_MAGIC or length_data is None:
                        raise ValueError("invalid download request")
                    name_length = NAME_LENGTH.unpack(length_data)[0]
                    name_data = receive_exact(connection, name_length)
                    if name_length == 0 or name_data is None:
                        raise ValueError("invalid download request")
                    path = requested_file(name_data.decode("utf-8"))
                    connection.sendall(b"\x01")
                    send_file_tcp(connection, path)
                    print(f"pync: sent {path}", file=sys.stderr)
                except (OSError, UnicodeError, ValueError) as exc:
                    message = str(exc).encode("utf-8", errors="replace")
                    try:
                        connection.sendall(b"\x00" + message)
                    except OSError:
                        pass


def listen_tcp(port: int, receive: Path | None) -> None:
    receiver = FileReceiver(receive) if receive else None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen()
        listener.settimeout(0.2)

        while True:
            try:
                connection, _address = listener.accept()
            except socket.timeout:
                continue

            with connection:
                connection.settimeout(0.2)
                if receiver:
                    while True:
                        length_data = receive_exact(connection, FRAME_LENGTH.size)
                        if length_data is None:
                            break
                        frame_size = FRAME_LENGTH.unpack(length_data)[0]
                        if not FILE_HEADER.size <= frame_size <= MAX_FRAME_SIZE:
                            raise ValueError("invalid file frame size")
                        packet = receive_exact(connection, frame_size)
                        if packet is None:
                            raise ValueError("incomplete file frame")
                        receiver.receive(packet)
                else:
                    while True:
                        try:
                            data = connection.recv(MAX_FRAME_SIZE)
                        except socket.timeout:
                            continue
                        if not data:
                            break
                        output_data(data)


def send_udp(address: str, port: int, upload: Path | None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        if upload:
            for packet in file_packets(upload):
                sender.sendto(packet, (address, port))
            return

        while True:
            data = sys.stdin.buffer.readline()
            if not data:
                return
            sender.sendto(data, (address, port))


def send_tcp(
    address: str, port: int, upload: Path | None, download: str | None
) -> None:
    with socket.create_connection((address, port)) as sender:
        sender.settimeout(0.2)
        if download is not None:
            filename = download.encode("utf-8")
            if not filename or len(filename) > 65535:
                raise ValueError("invalid download file name")
            sender.sendall(REQUEST_MAGIC + NAME_LENGTH.pack(len(filename)) + filename)
            status = receive_exact(sender, 1)
            if status is None:
                raise ValueError("server closed the connection without a response")
            if status != b"\x01":
                message = bytearray()
                while True:
                    try:
                        part = sender.recv(4096)
                    except socket.timeout:
                        continue
                    if not part:
                        break
                    message.extend(part)
                detail = message.decode("utf-8", errors="replace")
                raise ValueError(detail or "server rejected the download request")
            receive_file_tcp(sender, Path.cwd())
            return

        if upload:
            send_file_tcp(sender, upload)
            return

        while True:
            data = sys.stdin.buffer.readline()
            if not data:
                return
            sender.sendall(data)


def main() -> int:
    args = parse_args()
    try:
        if args.l:
            if args.server:
                serve_tcp(args.p)
            elif args.u:
                listen_udp(args.p, args.receive)
            else:
                listen_tcp(args.p, args.receive)
        elif args.u:
            send_udp(args.address, args.port, args.upload)
        else:
            send_tcp(args.address, args.port, args.upload, args.download)
    except KeyboardInterrupt:
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"pync: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
