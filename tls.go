package minq

import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

// #include <stdio.h>
// #include <stdlib.h>
// #include <memory.h>
// #include <unistd.h>
// #include "mitlsffi.h"
// #cgo CFLAGS: -I${SRCDIR}/../../../../../mitls-fstar/libs/ffi
// #cgo LDFLAGS: -L. -lmitls
import "C"

type TlsConfig struct {
	sni string
	cipher_suites string
	signature_algs string
	named_groups string
	enable_0rtt bool
	ca_file string
	certificate_file string
	private_key_file string
	//TODO(adl) transport_parameters, ticket_key, tivcket
}

func NewTlsConfig(serverName string) TlsConfig {
	return TlsConfig{
		serverName,
	}
}

type tlsConn struct {
	conn     *connBuffer
	tls      *C.quic_state
	finished bool
}

func newTlsConn(conf TlsConfig, role uint8) *tlsConn {
	var oqp [1024]C.char
	var ticket [1020]C.char

	t := C.quic_ticket{
		len: (C.size_t)(0),
		ticket: ticket,
	}

	qtp := C.quic_transport_parameters{
		max_stream_data: C.uint(1048576),
		max_data: C.uint(16777216),
		max_stream_id: C.uint(429496725),
		idle_timeout: C.ushort(60),
		others_len: (C.size_t)(0),
		others: oqp,
	}

	is_server := 0
	if role == RoleServer {
		is_server = 1
	}
	is_0rtt := 0
	if conf.enable_0rtt {
		is_0rtt = 1
	}

	c_cs := C.CString(conf.cipher_suites)
	defer C.free(unsafe.Pointer(c_cs))
	c_sa := C.CString(conf.signature_algs)
	defer C.free(unsafe.Pointer(c_sa))
	c_ng := C.CString(conf.named_groups)
	defer C.free(unsafe.Pointer(c_ng))
	c_sni := C.CString(conf.sni)
	defer C.free(unsafe.Pointer(c_sni))
	c_ca := C.CString(conf.ca_file)
	defer C.free(unsafe.Pointer(c_ca))
	c_crt := C.CString(conf.certificate_file)
	defer C.free(unsafe.Pointer(c_crt))
	c_key := C.CString(conf.private_key_file)
	defer C.free(unsafe.Pointer(c_key))
	c_enc := C.CString("CHACHA20-POLY1305")
	defer C.free(unsafe.Pointer(c_enc))


	cfg := &C.quic_config{
		is_server: C.int(is_server),
		qp: qtp,
		cipher_suites: c_cs,
		signature_algorithms: c_sa,
		named_groups: c_ng,
		enable_0rtt: C.int(is_0rtt),
		host_name: c_sni,
		ca_file: c_ca,
		server_ticket: t,
		certificate_chain_file: c_crt,
		private_key_file: c_key,
		ticket_enc_alg: c_enc,
		ticket_key: nil,
		ticket_key_len: 0,
	}

	c := newConnBuffer()
	var st *C.quic_state
	var err *C.char
	ret := int(C.FFI_mitls_quic_create(&st, cfg, &err))
	if ret == 0 {
		logf(logTypeTls, "TLS configure failed: %s", C.GoString(err))
		return nil
	}

	return &tlsConn {
		c,
		st,
		false,
	}
}

func (c *tlsConn) handshake(input []byte) ([]byte, error) {
	logf(logTypeTls, "TLS handshake input len=%v", len(input))
	logf(logTypeTrace, "TLS handshake input = %v", hex.EncodeToString(input))

	var outbuf [8192]byte
	c_outbuf := (*C.char)(C.CBytes(outbuf[:]))
	defer C.free(unsafe.Pointer(c_outbuf))
	c_inbuf := (*C.char)(C.CBytes(input))
	defer C.free(unsafe.Pointer(c_inbuf))

	var err *C.char
	written := (C.size_t)(8192)
	read := (C.size_t)(len(input))

	ret := C.FFI_mitls_quic_process(c.tls, c_inbuf, &read, c_outbuf, &written,  &err)

	logf(logTypeTls, "TLS wrote %d bytes", int(written))
	output := C.GoBytes(unsafe.Pointer(c_outbuf), C.int(written))
	logf(logTypeTrace, "TLS handshake output = %v", hex.EncodeToString(output))

	switch ret {
	case C.TLS_would_block:
                logf(logTypeTls, "TLS would have blocked")
	case C.TLS_error_local:
		return nil, fmt.Errorf("TLS sent an alert: %s", C.GoString(err))
	case C.TLS_error_alert:
		return nil, fmt.Errorf("TLS received an alert %s", C.GoString(err))
	case C.TLS_client_complete:
		logf(logTypeTls, "TLS: client complete")
		c.finished = true
	default:
		return nil, fmt.Errorf("Unhandled TLS return code: %d", ret)
	}

	return output, nil
}

func (c *tlsConn) computeExporter(label string) ([]byte, error) {
	var s C.quic_secret
	var err *C.char

	ret := C.FFI_mitls_quic_get_exporter(c.tls, 0, &s, &err)
	if ret == 0 {
		return nil, fmt.Errorf("TLS failed to get exporter: %s", C.GoString(err))
	}

	return nil, fmt.Errorf("NYI")
}

