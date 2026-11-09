#include "net/stun.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>

static uint32_t const s_crc32_table[256] = {
    0x00000000U, 0x77073096U, 0xEE0E612CU, 0x990951BAU, 0x076DC419U, 0x706AF48FU, 0xE963A535U,
    0x9E6495A3U, 0x0EDB8832U, 0x79DCB8A4U, 0xE0D5E91EU, 0x97D2D988U, 0x09B64C2BU, 0x7EB17CBDU,
    0xE7B82D07U, 0x90BF1D91U, 0x1DB71064U, 0x6AB020F2U, 0xF3B97148U, 0x84BE41DEU, 0x1ADAD47DU,
    0x6DDDE4EBU, 0xF4D4B551U, 0x83D385C7U, 0x136C9856U, 0x646BA8C0U, 0xFD62F97AU, 0x8A65C9ECU,
    0x14015C4FU, 0x63066CD9U, 0xFA0F3D63U, 0x8D080DF5U, 0x3B6E20C8U, 0x4C69105EU, 0xD56041E4U,
    0xA2677172U, 0x3C03E4D1U, 0x4B04D447U, 0xD20D85FDU, 0xA50AB56BU, 0x35B5A8FAU, 0x42B2986CU,
    0xDBBBC9D6U, 0xACBCF940U, 0x32D86CE3U, 0x45DF5C75U, 0xDCD60DCFU, 0xABD13D59U, 0x26D930ACU,
    0x51DE003AU, 0xC8D75180U, 0xBFD06116U, 0x21B4F4B5U, 0x56B3C423U, 0xCFBA9599U, 0xB8BDA50FU,
    0x2802B89EU, 0x5F058808U, 0xC60CD9B2U, 0xB10BE924U, 0x2F6F7C87U, 0x58684C11U, 0xC1611DABU,
    0xB6662D3DU, 0x76DC4190U, 0x01DB7106U, 0x98D220BCU, 0xEFD5102AU, 0x71B18589U, 0x06B6B51FU,
    0x9FBFE4A5U, 0xE8B8D433U, 0x7807C9A2U, 0x0F00F934U, 0x9609A88EU, 0xE10E9818U, 0x7F6A0DBBU,
    0x086D3D2DU, 0x91646C97U, 0xE6635C01U, 0x6B6B51F4U, 0x1C6C6162U, 0x856530D8U, 0xF262004EU,
    0x6C0695EDU, 0x1B01A57BU, 0x8208F4C1U, 0xF50FC457U, 0x65B0D9C6U, 0x12B7E950U, 0x8BBEB8EAU,
    0xFCB9887CU, 0x62DD1DDFU, 0x15DA2D49U, 0x8CD37CF3U, 0xFBD44C65U, 0x4DB26158U, 0x3AB551CEU,
    0xA3BC0074U, 0xD4BB30E2U, 0x4ADFA541U, 0x3DD895D7U, 0xA4D1C46DU, 0xD3D6F4FBU, 0x4369E96AU,
    0x346ED9FCU, 0xAD678846U, 0xDA60B8D0U, 0x44042D73U, 0x33031DE5U, 0xAA0A4C5FU, 0xDD0D7CC9U,
    0x5005713CU, 0x270241AAU, 0xBE0B1010U, 0xC90C2086U, 0x5768B525U, 0x206F85B3U, 0xB966D409U,
    0xCE61E49FU, 0x5EDEF90EU, 0x29D9C998U, 0xB0D09822U, 0xC7D7A8B4U, 0x59B33D17U, 0x2EB40D81U,
    0xB7BD5C3BU, 0xC0BA6CADU, 0xEDB88320U, 0x9ABFB3B6U, 0x03B6E20CU, 0x74B1D29AU, 0xEAD54739U,
    0x9DD277AFU, 0x04DB2615U, 0x73DC1683U, 0xE3630B12U, 0x94643B84U, 0x0D6D6A3EU, 0x7A6A5AA8U,
    0xE40ECF0BU, 0x9309FF9DU, 0x0A00AE27U, 0x7D079EB1U, 0xF00F9344U, 0x8708A3D2U, 0x1E01F268U,
    0x6906C2FEU, 0xF762575DU, 0x806567CBU, 0x196C3671U, 0x6E6B06E7U, 0xFED41B76U, 0x89D32BE0U,
    0x10DA7A5AU, 0x67DD4ACCU, 0xF9B9DF6FU, 0x8EBEEFF9U, 0x17B7BE43U, 0x60B08ED5U, 0xD6D6A3E8U,
    0xA1D1937EU, 0x38D8C2C4U, 0x4FDFF252U, 0xD1BB67F1U, 0xA6BC5767U, 0x3FB506DDU, 0x48B2364BU,
    0xD80D2BDAU, 0xAF0A1B4CU, 0x36034AF6U, 0x41047A60U, 0xDF60EFC3U, 0xA867DF55U, 0x316E8EEFU,
    0x4669BE79U, 0xCB61B38CU, 0xBC66831AU, 0x256FD2A0U, 0x5268E236U, 0xCC0C7795U, 0xBB0B4703U,
    0x220216B9U, 0x5505262FU, 0xC5BA3BBEU, 0xB2BD0B28U, 0x2BB45A92U, 0x5CB36A04U, 0xC2D7FFA7U,
    0xB5D0CF31U, 0x2CD99E8BU, 0x5BDEAE1DU, 0x9B64C2B0U, 0xEC63F226U, 0x756AA39CU, 0x026D930AU,
    0x9C0906A9U, 0xEB0E363FU, 0x72076785U, 0x05005713U, 0x95BF4A82U, 0xE2B87A14U, 0x7BB12BAEU,
    0x0CB61B38U, 0x92D28E9BU, 0xE5D5BE0DU, 0x7CDCEFB7U, 0x0BDBDF21U, 0x86D3D2D4U, 0xF1D4E242U,
    0x68DDB3F8U, 0x1FDA836EU, 0x81BE16CDU, 0xF6B9265BU, 0x6FB077E1U, 0x18B74777U, 0x88085AE6U,
    0xFF0F6A70U, 0x66063BCAU, 0x11010B5CU, 0x8F659EFFU, 0xF862AE69U, 0x616BFFD3U, 0x166CCF45U,
    0xA00AE278U, 0xD70DD2EEU, 0x4E048354U, 0x3903B3C2U, 0xA7672661U, 0xD06016F7U, 0x4969474DU,
    0x3E6E77DBU, 0xAED16A4AU, 0xD9D65ADCU, 0x40DF0B66U, 0x37D83BF0U, 0xA9BCAE53U, 0xDEBB9EC5U,
    0x47B2CF7FU, 0x30B5FFE9U, 0xBDBDF21CU, 0xCABAC28AU, 0x53B39330U, 0x24B4A3A6U, 0xBAD03605U,
    0xCDD70693U, 0x54DE5729U, 0x23D967BFU, 0xB3667A2EU, 0xC4614AB8U, 0x5D681B02U, 0x2A6F2B94U,
    0xB40BBE37U, 0xC30C8EA1U, 0x5A05DF1BU, 0x2D02EF8DU};

uint32_t stun_crc32(void const *restrict const data, size_t const len) {
    if (unlikely((data == nullptr) || (len == 0))) {
        return 0;
    }
    auto const bytes = (uint8_t const *)data;
    uint32_t   crc   = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; ++i) {
        crc = s_crc32_table[(crc ^ bytes[i]) & 0xFFU] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFU;
}

bool stun_is_binding_request(void const *restrict const data, size_t const len) {
    if (unlikely((data == nullptr) || (len < STUN_HEADER_SIZE))) {
        return false;
    }

    auto const bytes = (uint8_t const *)data;
    // STUN message first two bits must be 00 per RFC 5389 / RFC 7983
    if (unlikely((bytes[0] & 0xC0) != 0)) {
        return false;
    }

    uint16_t msg_type     = 0;
    uint16_t msg_len      = 0;
    uint32_t magic_cookie = 0;
    __builtin_memcpy(&msg_type, bytes, sizeof(msg_type));
    __builtin_memcpy(&msg_len, bytes + 2, sizeof(msg_len));
    __builtin_memcpy(&magic_cookie, bytes + 4, sizeof(magic_cookie));

    if (unlikely(ntohl(magic_cookie) != STUN_MAGIC_COOKIE)) {
        return false;
    }

    if (unlikely(ntohs(msg_type) != STUN_MSG_BINDING_REQUEST)) {
        return false;
    }

    size_t const msg_payload_len = (size_t)ntohs(msg_len);
    return ((msg_payload_len + STUN_HEADER_SIZE) <= len);
}

bool stun_parse_request(
    void const *restrict const data,
    size_t const len,
    stun_request_t *restrict const req) {
    if (unlikely((data == nullptr) || (len < STUN_HEADER_SIZE) || (req == nullptr))) {
        return false;
    }

    if (unlikely(!stun_is_binding_request(data, len))) {
        return false;
    }

    *req             = (stun_request_t){};
    auto const bytes = (uint8_t const *)data;
    __builtin_memcpy(req->tx_id, bytes + 8, STUN_TX_ID_LEN);

    uint16_t raw_msg_len = 0;
    __builtin_memcpy(&raw_msg_len, bytes + 2, sizeof(raw_msg_len));

    size_t const total_attrs_len = (size_t)ntohs(raw_msg_len);
    size_t const end_offset      = STUN_HEADER_SIZE + total_attrs_len;
    if (unlikely(end_offset > len)) {
        return false;
    }

    size_t offset = STUN_HEADER_SIZE;

    while ((offset + sizeof(stun_attr_header_t)) <= end_offset) {
        uint16_t raw_type = 0;
        uint16_t raw_len  = 0;
        __builtin_memcpy(&raw_type, bytes + offset, sizeof(raw_type));
        __builtin_memcpy(&raw_len, bytes + offset + 2, sizeof(raw_len));

        uint16_t const attr_type = ntohs(raw_type);
        uint16_t const attr_len  = ntohs(raw_len);

        size_t const padded_len = (size_t)((attr_len + 3U) & ~3U);
        size_t const attr_end   = offset + sizeof(stun_attr_header_t) + padded_len;
        if (unlikely(attr_end > end_offset)) {
            break;
        }

        uint8_t const *const val = bytes + offset + sizeof(stun_attr_header_t);

        switch (attr_type) {
        case STUN_ATTR_USERNAME: {
            req->has_username = true;
            size_t const copy_len =
                (attr_len < (sizeof(req->username) - 1)) ? attr_len : (sizeof(req->username) - 1);
            __builtin_memcpy(req->username, val, copy_len);
            req->username[copy_len] = '\0';
            break;
        }
        case STUN_ATTR_PRIORITY: {
            if (attr_len >= 4) {
                uint32_t prio = 0;
                __builtin_memcpy(&prio, val, sizeof(prio));
                req->priority     = ntohl(prio);
                req->has_priority = true;
            }
            break;
        }
        case STUN_ATTR_USE_CANDIDATE:
            req->has_use_candidate = true;
            break;
        case STUN_ATTR_MESSAGE_INTEGRITY:
            req->has_message_integrity = true;
            break;
        case STUN_ATTR_FINGERPRINT:
            req->has_fingerprint = true;
            break;
        default:
            break;
        }

        offset = attr_end;
    }

    return true;
}

bool stun_build_binding_response(
    uint8_t const *restrict const tx_id,
    struct sockaddr_storage const *restrict const src_addr,
    socklen_t const   src_len,
    char const *const ice_pwd,
    void *restrict const out_buf,
    size_t const out_cap,
    size_t *restrict const out_len) {
    if (unlikely(
            (tx_id == nullptr) || (src_addr == nullptr) || (src_len == 0) || (out_buf == nullptr) ||
            (out_cap < (STUN_HEADER_SIZE + 12))))
    {
        return false;
    }

    auto const out_bytes = (uint8_t *)out_buf;

    uint16_t const msg_type     = htons(STUN_MSG_BINDING_RESPONSE);
    uint16_t const initial_len  = 0;
    uint32_t const magic_cookie = htonl(STUN_MAGIC_COOKIE);

    __builtin_memcpy(out_bytes, &msg_type, sizeof(msg_type));
    __builtin_memcpy(out_bytes + 2, &initial_len, sizeof(initial_len));
    __builtin_memcpy(out_bytes + 4, &magic_cookie, sizeof(magic_cookie));
    __builtin_memcpy(out_bytes + 8, tx_id, STUN_TX_ID_LEN);

    size_t offset = STUN_HEADER_SIZE;

    // Append XOR-MAPPED-ADDRESS attribute
    if (src_addr->ss_family == AF_INET) {
        if (unlikely((offset + sizeof(stun_attr_header_t) + 8) > out_cap)) {
            return false;
        }
        auto const sin = (struct sockaddr_in const *)src_addr;

        uint16_t const attr_type = htons(STUN_ATTR_XOR_MAPPED_ADDRESS);
        uint16_t const attr_len  = htons(8);
        __builtin_memcpy(out_bytes + offset, &attr_type, sizeof(attr_type));
        __builtin_memcpy(out_bytes + offset + 2, &attr_len, sizeof(attr_len));
        offset += sizeof(stun_attr_header_t);

        out_bytes[offset]     = 0x00; // Reserved
        out_bytes[offset + 1] = 0x01; // IPv4

        uint16_t const x_port =
            (uint16_t)(sin->sin_port ^ htons((uint16_t)(STUN_MAGIC_COOKIE >> 16)));
        __builtin_memcpy(out_bytes + offset + 2, &x_port, sizeof(x_port));

        uint32_t const x_addr = (uint32_t)(sin->sin_addr.s_addr ^ htonl(STUN_MAGIC_COOKIE));
        __builtin_memcpy(out_bytes + offset + 4, &x_addr, sizeof(x_addr));

        offset += 8;
    } else if (src_addr->ss_family == AF_INET6) {
        if (unlikely((offset + sizeof(stun_attr_header_t) + 20) > out_cap)) {
            return false;
        }
        auto const sin6 = (struct sockaddr_in6 const *)src_addr;

        uint16_t const attr_type = htons(STUN_ATTR_XOR_MAPPED_ADDRESS);
        uint16_t const attr_len  = htons(20);
        __builtin_memcpy(out_bytes + offset, &attr_type, sizeof(attr_type));
        __builtin_memcpy(out_bytes + offset + 2, &attr_len, sizeof(attr_len));
        offset += sizeof(stun_attr_header_t);

        out_bytes[offset]     = 0x00; // Reserved
        out_bytes[offset + 1] = 0x02; // IPv6

        uint16_t const x_port =
            (uint16_t)(sin6->sin6_port ^ htons((uint16_t)(STUN_MAGIC_COOKIE >> 16)));
        __builtin_memcpy(out_bytes + offset + 2, &x_port, sizeof(x_port));

        // First 4 bytes XOR with magic cookie
        uint32_t       cookie_net   = htonl(STUN_MAGIC_COOKIE);
        uint8_t const *cookie_bytes = (uint8_t const *)&cookie_net;
        for (size_t i = 0; i < 4; ++i) {
            out_bytes[offset + 4 + i] = (uint8_t)(sin6->sin6_addr.s6_addr[i] ^ cookie_bytes[i]);
        }
        // Remaining 12 bytes XOR with transaction ID
        for (size_t i = 0; i < 12; ++i) {
            out_bytes[offset + 8 + i] = (uint8_t)(sin6->sin6_addr.s6_addr[4 + i] ^ tx_id[i]);
        }

        offset += 20;
    } else {
        return false;
    }

    // If ICE password is provided, append MESSAGE-INTEGRITY
    if ((ice_pwd != nullptr) && (ice_pwd[0] != '\0')) {
        size_t const mi_total = sizeof(stun_attr_header_t) + 20; // 24 bytes
        if (likely((offset + mi_total) <= out_cap)) {
            // Per RFC 5389 Section 15.4: Length in header covers message up to end of
            // MESSAGE-INTEGRITY
            size_t const   attrs_len_with_mi = (offset - STUN_HEADER_SIZE) + mi_total;
            uint16_t const mi_net_len        = htons((uint16_t)attrs_len_with_mi);
            __builtin_memcpy(out_bytes + 2, &mi_net_len, sizeof(mi_net_len));

            unsigned char hmac[EVP_MAX_MD_SIZE] = {};
            unsigned int  hmac_len              = 0;
            size_t const  pwd_len               = __builtin_strlen(ice_pwd);

            (void)HMAC(EVP_sha1(), ice_pwd, (int)pwd_len, out_bytes, offset, hmac, &hmac_len);

            uint16_t const mi_type = htons(STUN_ATTR_MESSAGE_INTEGRITY);
            uint16_t const mi_len  = htons(20);
            __builtin_memcpy(out_bytes + offset, &mi_type, sizeof(mi_type));
            __builtin_memcpy(out_bytes + offset + 2, &mi_len, sizeof(mi_len));
            offset += sizeof(stun_attr_header_t);
            __builtin_memcpy(out_bytes + offset, hmac, 20);
            offset += 20;
        }
    }

    // Always append FINGERPRINT per RFC 5389 Section 15.5 and RFC 8445
    size_t const fp_total = sizeof(stun_attr_header_t) + 4; // 8 bytes
    if (likely((offset + fp_total) <= out_cap)) {
        size_t const   attrs_len_with_fp = (offset - STUN_HEADER_SIZE) + fp_total;
        uint16_t const fp_net_len        = htons((uint16_t)attrs_len_with_fp);
        __builtin_memcpy(out_bytes + 2, &fp_net_len, sizeof(fp_net_len));

        uint32_t const crc = stun_crc32(out_bytes, offset) ^ STUN_FINGERPRINT_XOR;

        uint16_t const fp_type = htons(STUN_ATTR_FINGERPRINT);
        uint16_t const fp_len  = htons(4);
        __builtin_memcpy(out_bytes + offset, &fp_type, sizeof(fp_type));
        __builtin_memcpy(out_bytes + offset + 2, &fp_len, sizeof(fp_len));
        offset += sizeof(stun_attr_header_t);

        uint32_t const crc_net = htonl(crc);
        __builtin_memcpy(out_bytes + offset, &crc_net, sizeof(crc_net));
        offset += 4;
    }

    uint16_t const final_len = htons((uint16_t)(offset - STUN_HEADER_SIZE));
    __builtin_memcpy(out_bytes + 2, &final_len, sizeof(final_len));

    if (out_len != nullptr) {
        *out_len = offset;
    }
    return true;
}
