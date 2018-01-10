#ifndef SSTP_PROT_H
#define SSTP_PROT_H

#include <stdint.h>

/* Constants */
#define SSTP_PORT			443
#define SSTP_HTTP_METHOD		"SSTP_DUPLEX_POST"
#define SSTP_HTTP_URI			"/sra_{BA195980-CD49-458b-9E23-C84EE0ADCD75}/"
#define SSTP_VERSION			0x10
#define SSTP_MAX_PACKET_SIZE		4095
#define SSTP_NONCE_SIZE			32
#define SSTP_NEGOTIOATION_TIMEOUT	60
#define SSTP_HELLO_TIMEOUT		60
#define SSTP_ABORT_TIMEOUT_1		3
#define SSTP_ABORT_TIMEOUT_2		1
#define SSTP_DISCONNECT_TIMEOUT_1	5
#define SSTP_DISCONNECT_TIMEOUT_2	1

/* Packet Type */
enum {
	SSTP_DATA_PACKET = 0x00,
	SSTP_CTRL_PACKET = 0x01,
};

/* Message Type */
enum {
	SSTP_MSG_CALL_CONNECT_REQUEST = 0x0001,
	SSTP_MSG_CALL_CONNECT_ACK = 0x0002,
	SSTP_MSG_CALL_CONNECT_NAK = 0x0003,
	SSTP_MSG_CALL_CONNECTED = 0x0004,
	SSTP_MSG_CALL_ABORT = 0x0005,
	SSTP_MSG_CALL_DISCONNECT = 0x0006,
	SSTP_MSG_CALL_DISCONNECT_ACK = 0x0007,
	SSTP_MSG_ECHO_REQUEST = 0x0008,
	SSTP_MSG_ECHO_RESPONSE = 0x0009,
};

/* Attribute ID */
enum {
	SSTP_ATTRIB_NO_ERROR = 0x00,
	SSTP_ATTRIB_ENCAPSULATED_PROTOCOL_ID = 0x01,
	SSTP_ATTRIB_STATUS_INFO = 0x02,
	SSTP_ATTRIB_CRYPTO_BINDING = 0x03,
	SSTP_ATTRIB_CRYPTO_BINDING_REQ = 0x04,
};

/* Protocol ID */
enum {
	SSTP_ENCAPSULATED_PROTOCOL_PPP = 0x0001,
};

/* Hash Protocol Bitmask */
enum {
	CERT_HASH_PROTOCOL_SHA1 = 0x01,
	CERT_HASH_PROTOCOL_SHA256 = 0x02,
};

/* Status */
enum {
	ATTRIB_STATUS_NO_ERROR = 0x00000000,
	ATTRIB_STATUS_DUPLICATE_ATTRIBUTE = 0x00000001,
	ATTRIB_STATUS_UNRECOGNIZED_ATTRIBUTE = 0x00000002,
	ATTRIB_STATUS_INVALID_ATTRIB_VALUE_LENGTH = 0x00000003,
	ATTRIB_STATUS_VALUE_NOT_SUPPORTED = 0x00000004,
	ATTRIB_STATUS_UNACCEPTED_FRAME_RECEIVED = 0x00000005,
	ATTRIB_STATUS_RETRY_COUNT_EXCEEDED = 0x00000006,
	ATTRIB_STATUS_INVALID_FRAME_RECEIVED = 0x00000007,
	ATTRIB_STATUS_NEGOTIATION_TIMEOUT = 0x00000008,
	ATTRIB_STATUS_ATTRIB_NOT_SUPPORTED_IN_MSG = 0x00000009,
	ATTRIB_STATUS_REQUIRED_ATTRIBUTE_MISSING = 0x0000000a,
	ATTRIB_STATUS_STATUS_INFO_NOT_SUPPORTED_IN_MSG = 0x0000000b,
};

/* State */
enum {
	STATE_SERVER_CALL_DISCONNECTED = 0,
	STATE_SERVER_CONNECT_REQUEST_PENDING,
	STATE_SERVER_CALL_CONNECTED_PENDING,
	STATE_SERVER_CALL_CONNECTED,
	STATE_CALL_ABORT_IN_PROGRESS_1,
	STATE_CALL_ABORT_IN_PROGRESS_2,
	STATE_CALL_ABORT_TIMEOUT_PENDING,
	STATE_CALL_ABORT_PENDING,
	STATE_CALL_DISCONNECT_IN_PROGRESS_1,
	STATE_CALL_DISCONNECT_IN_PROGRESS_2,
	STATE_CALL_DISCONNECT_TIMEOUT_PENDING,
	STATE_CALL_DISCONNECT_ACK_PENDING,
};

/* Packets */
struct sstp_hdr {
	uint8_t version;
	uint8_t reserved;
	uint16_t length;
	uint8_t data[0];
} __attribute__((packed));

struct sstp_ctrl_hdr {
	uint8_t version;
	uint8_t reserved;
	uint16_t length;
	uint16_t message_type;
	uint16_t num_attributes;
	uint8_t data[0];
} __attribute__((packed));

struct sstp_attr_hdr {
	uint8_t reserved;
	uint8_t attribute_id;
	uint16_t length;
	uint8_t data[0];
} __attribute__((packed));

struct sstp_attrib_encapsulated_protocol {
	struct sstp_attr_hdr hdr;
	uint16_t protocol_id;
} __attribute__((packed));

struct sstp_attrib_status_info {
	struct sstp_attr_hdr hdr;
	uint8_t reserved[3];
	uint8_t attrib_id;
	uint32_t status;
	uint8_t attrib_value[0];
} __attribute__((packed));

struct sstp_attrib_crypto_binding {
	struct sstp_attr_hdr hdr;
	uint8_t reserved[3];
	uint8_t hash_protocol_bitmask;
	uint8_t nonce[SSTP_NONCE_SIZE];
	uint8_t cert_hash[32];
	uint8_t compound_mac[32];
} __attribute__((packed));

struct sstp_attrib_crypto_binding_request {
	struct sstp_attr_hdr hdr;
	uint8_t reserved[3];
	uint8_t hash_protocol_bitmask;
	uint8_t nonce[SSTP_NONCE_SIZE];
} __attribute__((packed));

#define SSTP_DATA_HDR(len) {		\
	.version = SSTP_VERSION,	\
	.reserved = SSTP_DATA_PACKET,	\
	.length = htons(len),		\
}

#define SSTP_CTRL_HDR(type, len, num) {	\
	.version = SSTP_VERSION,	\
	.reserved = SSTP_CTRL_PACKET,	\
	.length = htons(len),		\
	.message_type = htons(type),	\
	.num_attributes = htons(num)	\
}

#define SSTP_ATTR_HDR(id, len) {	\
	.attribute_id = id,		\
	.length = htons(len)		\
}

#define INIT_SSTP_DATA_HDR(hdr, len) {		\
	(hdr)->version = SSTP_VERSION;		\
	(hdr)->reserved = SSTP_DATA_PACKET;	\
	(hdr)->length = htons(len);		\
}

#define INIT_SSTP_CTRL_HDR(hdr, type, num, len) {\
	(hdr)->version = SSTP_VERSION;		\
	(hdr)->reserved = SSTP_CTRL_PACKET;	\
	(hdr)->length = htons(len);		\
	(hdr)->message_type = htons(type);	\
	(hdr)->num_attributes = htons(num);	\
}

#define INIT_SSTP_ATTR_HDR(hdr, id, len) {	\
	(hdr)->attribute_id = id;		\
	(hdr)->length = htons(len);		\
}

#endif
