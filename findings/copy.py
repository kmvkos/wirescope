"""Russian operator-facing copy for finding catalog strings.

`rule_id`, JSON keys, observation field names, and protocol tokens stay
English. Titles, descriptions, rationales, and recommendations are Russian.
"""

from typing import Any


SSH_WEAK = {
    "title": "Предлагаются слабые алгоритмы SSH",
    "description": (
        "Служба SSH объявляет заведомо слабые алгоритмы обмена ключами, "
        "ключа узла, шифрования или MAC."
    ),
    "recommendation": (
        "Отключите SHA-1, CBC, RC4, 3DES, DSS и связанные устаревшие "
        "алгоритмы. Предпочитайте curve25519, rsa-sha2, AES-GCM или "
        "chacha20-poly1305 и MAC на SHA-2."
    ),
}

TLS_LEGACY = {
    "title": "Согласован устаревший протокол TLS",
    "description": (
        "Рукопожатие TLS согласовало протокол старше TLS 1.2."
    ),
    "recommendation": (
        "Отключите SSLv3, TLS 1.0 и TLS 1.1. Оставляйте только TLS 1.2 "
        "и TLS 1.3."
    ),
}

TLS_WEAK_CIPHER = {
    "title": "Согласован слабый шифр TLS",
    "description": (
        "Рукопожатие TLS выбрало набор шифров с NULL, EXPORT, RC4, DES, "
        "3DES, MD5 или анонимным DH."
    ),
    "recommendation": (
        "Отключите устаревшие наборы шифров и предпочитайте AEAD, "
        "например AES-GCM или ChaCha20-Poly1305."
    ),
}

TLS_CERT_EXPIRED = {
    "title": "Срок действия сертификата TLS истёк",
    "description": (
        "Дата notAfter предъявленного сертификата TLS раньше времени оценки."
    ),
    "recommendation": (
        "Замените сертификат до истечения срока и автоматизируйте продление."
    ),
}

TLS_CERT_UNTRUSTED = {
    "title": "Сертификат TLS не прошёл проверку",
    "description": (
        "OpenSSL вернул ненулевой код проверки сертификата для этой службы."
    ),
    "recommendation": (
        "Установите сертификат, выданный доверенным УЦ, либо задокументируйте "
        "закрытый PKI, если это ожидаемый внутренний якорь доверия."
    ),
}

HTTP_MISSING_HSTS = {
    "title": "Служба HTTPS не отдаёт HSTS",
    "description": (
        "Ответ HTTPS не содержал заголовок Strict-Transport-Security."
    ),
    "recommendation": (
        "Отправляйте Strict-Transport-Security с консервативным max-age на "
        "слушателях HTTPS. Не включайте HSTS на обычном HTTP."
    ),
}

HTTP_MISSING_HEADERS = {
    "title": "Неполные заголовки безопасности HTTP",
    "description": (
        "Ответ HTTP не содержал обычных заголовков против clickjacking "
        "или политики содержимого."
    ),
    "recommendation": (
        "Добавьте Content-Security-Policy и либо X-Frame-Options, либо "
        "CSP frame-ancestors."
    ),
}

HTTP_SERVER_DISCLOSURE = {
    "title": "Раскрывается идентичность HTTP-сервера",
    "description": "Ответ HTTP содержит Server или X-Powered-By.",
    "recommendation": (
        "Уберите или обезличьте Server и X-Powered-By, если они не нужны "
        "для совместимости."
    ),
}

SMB_NULL_SESSION = {
    "title": "Принята нулевая сессия SMB",
    "description": (
        "Неаутентифицированный просмотр SMB к этой службе завершился успешно."
    ),
    "recommendation": (
        "Отключите анонимные/нулевые сессии SMB и ограничьте перечень "
        "ресурсов аутентифицированными пользователями."
    ),
}

SMB_SIGNING = {
    "title": "Подпись SMB не обязательна",
    "description": (
        "Нормализованные наблюдения SMB указывают, что подпись отключена "
        "или не требуется."
    ),
    "recommendation": "Требуйте подпись SMB на этой службе.",
}

SMB_LEGACY = {
    "title": "Предлагается устаревший диалект SMB",
    "description": "Служба, по-видимому, предлагает SMBv1 или LANMAN.",
    "recommendation": "Отключите SMBv1 и другие устаревшие диалекты.",
}

DNS_RECURSION = {
    "title": "Доступна рекурсия DNS",
    "description": "Резолвер установил флаг Recursion Available.",
    "recommendation": (
        "Отключите рекурсию на авторитативных серверах либо ограничьте "
        "рекурсивный сервис доверенными клиентами."
    ),
}

DNS_VERSION = {
    "title": "Раскрывается идентичность DNS CHAOS",
    "description": "Резолвер ответил на запросы идентичности CHAOS TXT.",
    "recommendation": (
        "Отключите ответы CHAOS version.bind / id.server, если они не "
        "нужны для эксплуатации."
    ),
}

SNMP_UNAUTH = {
    "title": "SNMP ответил без аутентификации",
    "description": "Зонд SNMPv3 noAuthNoPriv получил ответ.",
    "recommendation": (
        "Требуйте аутентификацию и конфиденциальность SNMPv3 и ограничьте "
        "SNMP сетями управления. Подбор community не входит в профиль "
        "по умолчанию."
    ),
}

LDAP_ANON = {
    "title": "Разрешён анонимный bind LDAP",
    "description": (
        "Анонимный поиск LDAP вернул атрибуты naming context каталога."
    ),
    "recommendation": (
        "Отключите анонимный bind либо ограничьте раскрытие root DSE "
        "аутентифицированными клиентами."
    ),
}

LLMNR = {
    "title": "Наблюдалось разрешение имён LLMNR",
    "description": (
        "Пассивный захват зафиксировал LLMNR, уязвимый к подмене имён "
        "в локальном сегменте."
    ),
    "recommendation": (
        "Отключите LLMNR на конечных узлах и предпочитайте аутентифицированный DNS."
    ),
}

NBNS = {
    "title": "Наблюдалась служба имён NetBIOS",
    "description": (
        "Пассивный захват зафиксировал трафик NBNS/NetBIOS Name Service."
    ),
    "recommendation": (
        "Отключите разрешение имён NetBIOS там, где оно не используется, "
        "и рассматривайте NBNS как локальный протокол, подверженный отравлению."
    ),
}

MULTIPLE_DHCP = {
    "title": "Наблюдалось несколько DHCP-серверов",
    "description": (
        "Пассивные наблюдения DHCP содержат более одного идентификатора сервера."
    ),
    "recommendation": (
        "Проверьте, уполномочены ли несколько DHCP-серверов в этом сегменте. "
        "Посторонний DHCP — типичный риск ЛВС."
    ),
}


def ssh_rationale(families: str) -> str:
    return (
        "Нормализованные наблюдения ssh_algorithms перечислили слабые "
        f"алгоритмы в: {families}."
    )


def tls_legacy_rationale(protocol: str) -> str:
    return f"Наблюдения tls_session зафиксировали протокол {protocol}."


def tls_cipher_rationale(cipher: str) -> str:
    return f"Наблюдения tls_session зафиксировали шифр {cipher}."


def tls_expired_rationale(not_after: Any, evaluated_at: str) -> str:
    return (
        f"tls_certificate.not_after равен {not_after}, время оценки — "
        f"{evaluated_at}."
    )


def tls_untrusted_rationale(verify_code: Any, verify_message: Any) -> str:
    return (
        f"tls_certificate.verify_code равен {verify_code} "
        f"({verify_message})."
    )


def http_hsts_rationale() -> str:
    return (
        "Заголовки http_response нормализованы и не содержат "
        "strict-transport-security на службе HTTPS."
    )


def http_headers_rationale(missing: str) -> str:
    return f"Заголовки http_response не содержат: {missing}."


def http_disclosure_rationale(disclosed: str) -> str:
    return f"Заголовки http_response зафиксировали {disclosed}."


def smb_null_rationale(share_count: Any) -> str:
    extra = (
        f" с {share_count} ресурсами" if share_count is not None else ""
    )
    return f"smb_null_session.accepted равен true{extra}."


def smb_signing_rationale() -> str:
    return "Поле smb signing указывает, что подпись выключена."


def smb_dialect_rationale(dialect: Any) -> str:
    return f"Нормализованное поле dialect равно {dialect}."


def dns_recursion_rationale(flags: Any) -> str:
    extra = f" с флагами {flags}" if flags else ""
    return f"dns_flags.recursion_available равен true{extra}."


def dns_identity_rationale(version: Any, hostname: Any) -> str:
    return (
        "dns_identity зафиксировал version="
        f"{version!r} hostname={hostname!r}."
    )


def snmp_rationale(usm_indicator: Any) -> str:
    extra = (
        f" (usm_indicator={usm_indicator})" if usm_indicator else ""
    )
    return f"snmp_unauthenticated.responded равен true{extra}."


def ldap_rationale() -> str:
    return "ldap_rootdse/ldap_anonymous_bind.anonymous_bind равен true."


def management_title(name: str) -> str:
    return f"Открыта небезопасная служба управления {name}"


def management_description(name: str, protocol: str, port: int) -> str:
    return (
        f"В инвентаре зафиксирована открытая служба {name} на "
        f"{protocol}/{port}."
    )


def management_rationale(
    service_name: str,
    protocol: str,
    port: int,
) -> str:
    return (
        f"Нормализованная служба инвентаря {service_name} открыта на "
        f"{protocol}/{port}. Это не результат протокольного аудита; "
        "служба не подвергалась перебору."
    )


def management_recommendation(name: str) -> str:
    return (
        f"Отключите {name} в продуктивных сетях либо ограничьте её "
        "выделенной плоскостью управления с аутентификацией."
    )


def infra_rationale(sensor: str, status: str, hits: int) -> str:
    return (
        f"Сохранённый пассивный датчик {sensor} status={status} hits={hits}."
    )


def dhcp_rationale(count: int) -> str:
    return (
        "Нормализованная сводка датчика dhcpv4 перечислила "
        f"{count} различных идентификаторов серверов."
    )


STATIC_COPY = {
    "WS-SSH-WEAK-ALGORITHMS": SSH_WEAK,
    "WS-TLS-LEGACY-PROTOCOL": TLS_LEGACY,
    "WS-TLS-WEAK-CIPHER": TLS_WEAK_CIPHER,
    "WS-TLS-CERT-EXPIRED": TLS_CERT_EXPIRED,
    "WS-TLS-CERT-UNTRUSTED": TLS_CERT_UNTRUSTED,
    "WS-HTTP-MISSING-HSTS": HTTP_MISSING_HSTS,
    "WS-HTTP-MISSING-SECURITY-HEADERS": HTTP_MISSING_HEADERS,
    "WS-HTTP-SERVER-DISCLOSURE": HTTP_SERVER_DISCLOSURE,
    "WS-SMB-NULL-SESSION": SMB_NULL_SESSION,
    "WS-SMB-SIGNING-DISABLED": SMB_SIGNING,
    "WS-SMB-LEGACY-DIALECT": SMB_LEGACY,
    "WS-DNS-RECURSION": DNS_RECURSION,
    "WS-DNS-VERSION-DISCLOSED": DNS_VERSION,
    "WS-SNMP-UNAUTHENTICATED": SNMP_UNAUTH,
    "WS-LDAP-ANONYMOUS-BIND": LDAP_ANON,
    "WS-INFRA-LLMNR": LLMNR,
    "WS-INFRA-NBNS": NBNS,
    "WS-INFRA-MULTIPLE-DHCP": MULTIPLE_DHCP,
}

__all__ = [
    "DNS_RECURSION",
    "DNS_VERSION",
    "HTTP_MISSING_HEADERS",
    "HTTP_MISSING_HSTS",
    "HTTP_SERVER_DISCLOSURE",
    "LDAP_ANON",
    "LLMNR",
    "MULTIPLE_DHCP",
    "NBNS",
    "SMB_LEGACY",
    "SMB_NULL_SESSION",
    "SMB_SIGNING",
    "SNMP_UNAUTH",
    "SSH_WEAK",
    "STATIC_COPY",
    "TLS_CERT_EXPIRED",
    "TLS_CERT_UNTRUSTED",
    "TLS_LEGACY",
    "TLS_WEAK_CIPHER",
    "dhcp_rationale",
    "dns_identity_rationale",
    "dns_recursion_rationale",
    "http_disclosure_rationale",
    "http_headers_rationale",
    "http_hsts_rationale",
    "infra_rationale",
    "ldap_rationale",
    "management_description",
    "management_rationale",
    "management_recommendation",
    "management_title",
    "smb_dialect_rationale",
    "smb_null_rationale",
    "smb_signing_rationale",
    "snmp_rationale",
    "ssh_rationale",
    "tls_cipher_rationale",
    "tls_expired_rationale",
    "tls_legacy_rationale",
    "tls_untrusted_rationale",
]
