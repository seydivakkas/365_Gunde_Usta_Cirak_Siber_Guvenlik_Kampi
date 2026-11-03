"""TCP üçlü el sıkışmayı öğretmek için zararsız çevrimdışı durum simülasyonu.

Bu modül gerçek TCP paketi üretmez, ağ arayüzüne erişmez ve bağlantı kurmaz.
Gerçek TCP uygulamasının tüm sıra numarası davranışlarını modellemez.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_SEQ = 2**32


@dataclass(frozen=True)
class Packet:
    """Eğitim modelindeki basitleştirilmiş TCP kontrol alanları."""

    source: str
    destination: str
    sequence: int
    acknowledgement: int | None
    syn: bool
    ack: bool


def _validate_initial_sequence(value: int, name: str) -> None:
    if type(value) is not int or not 0 <= value < MAX_SEQ:
        raise ValueError(f"{name}, 0..{MAX_SEQ - 1} arasında tam sayı olmalıdır")


def create_handshake(client_isn: int = 100, server_isn: int = 200) -> tuple[Packet, ...]:
    """Güvenli eğitim ortamı için SYN → SYN-ACK → ACK modelini hazırlar."""

    _validate_initial_sequence(client_isn, "client_isn")
    _validate_initial_sequence(server_isn, "server_isn")

    return (
        Packet("client", "server", client_isn, None, syn=True, ack=False),
        Packet(
            "server", "client", server_isn, (client_isn + 1) % MAX_SEQ,
            syn=True, ack=True,
        ),
        Packet(
            "client", "server", (client_isn + 1) % MAX_SEQ,
            (server_isn + 1) % MAX_SEQ, syn=False, ack=True,
        ),
    )


def validate_handshake(packets: tuple[Packet, ...]) -> bool:
    """Basitleştirilmiş el sıkışma sırasını ve ACK ilişkisini doğrular."""

    if len(packets) != 3:
        return False
    syn, syn_ack, ack = packets
    if not (
        (syn.source, syn.destination, syn.syn, syn.ack)
        == ("client", "server", True, False)
    ):
        return False
    if not (
        (syn_ack.source, syn_ack.destination, syn_ack.syn, syn_ack.ack)
        == ("server", "client", True, True)
    ):
        return False
    if not (
        (ack.source, ack.destination, ack.syn, ack.ack)
        == ("client", "server", False, True)
    ):
        return False
    for item in packets:
        if not 0 <= item.sequence < MAX_SEQ:
            return False
    return (
        syn.acknowledgement is None
        and syn_ack.acknowledgement == (syn.sequence + 1) % MAX_SEQ
        and ack.sequence == (syn.sequence + 1) % MAX_SEQ
        and ack.acknowledgement == (syn_ack.sequence + 1) % MAX_SEQ
    )


def main() -> int:
    packets = create_handshake()
    for step, packet in enumerate(packets, 1):
        flags = "+".join(name for name, present in (
            ("SYN", packet.syn), ("ACK", packet.ack),
        ) if present)
        print(f"{step}. {packet.source} -> {packet.destination}  "
              f"flags={flags} seq={packet.sequence} "
              f"ack={packet.acknowledgement}")
    print("MODEL_KONTROL:", "PASS" if validate_handshake(packets) else "FAIL")
    return 0 if validate_handshake(packets) else 1


if __name__ == "__main__":
    raise SystemExit(main())
