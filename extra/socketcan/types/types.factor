USING: alien.c-types classes.struct unix.ffi unix.types ;
IN: socketcan.types

CONSTANT: IFNAMSIZ 16
UNION-STRUCT: ifrn-name
    { ifrn_name char[IFNAMSIZ] } ;

STRUCT: raw_hdlc_proto
    { encoding ushort }
    { parity ushort } ;
STRUCT: cisco_proto
    { interval uint }
    { timeout uint } ;
STRUCT: fr_proto
    { t391 uint }
    { t392 uint }
    { n391 uint }
    { n392 uint }
    { n393 uint }
    { lmi ushort }
    { dce ushort } ;
STRUCT: fr_proto_pvc
    { dlci uint } ;
STRUCT: fr_proto_pvc_inf
    { dlci uint }
    { master char*[IFNAMSIZ] } ;
STRUCT: x25_hdlc_proto
    { dce ushort }
    { modulo uint }
    { window uint }
    { t1 uint }
    { t2 uint }
    { n2 uint } ;
STRUCT: sync_serial_setting
    { clock_rate uint }
    { clock_type uint }
    { loopback ushort } ;
STRUCT: te1_settings
    { clock_rate uint }
    { clock_type uint }
    { loopback ushort }
    { slot_map uint } ;

UNION-STRUCT: ifs-ifsu
    { raw_hdlc raw_hdlc_proto* }
    { cisco cisco_proto* }
    { fr fr_proto* }
    { fr_pvc fr_proto_pvc* }
    { fr_pvc_info fr_proto_pvc_inf* }
    { x25 x25_hdlc_proto* }
    { sync sync_serial_setting* }
    { te1 te1_settings* } ;

STRUCT: if-settings
    { type uint }
    { size uint }
    { ifsu ifs-ifsu } ;
UNION-STRUCT: ifru
    { ifru-addr sockaddr-un }
    { ifru-dstaddr sockaddr-un }
    { ifru-broadaddr sockaddr-un }
    { ifru-netmask sockaddr-un }
    { ifru-hwaddr sockaddr-un }
    { flags short }
    { ivalue int }
    { slave char[IFNAMSIZ] }
    { newname char[IFNAMSIZ] }
    { data void* }
    { settings if-settings } ;
STRUCT: ifreq
    { ifr_ifrn ifrn-name }
    { ifr_ifru ifru } ;

CONSTANT: CAN_MAX_DLEN 8
CONSTANT: CAN_EFF_FLAG 0x80000000
CONSTANT: CAN_RTR_FLAG 0x40000000
CONSTANT: CAN_ERR_FLAG 0x20000000
CONSTANT: CAN_SFF_MASK 0x000007FF
CONSTANT: CAN_EFF_MASK 0x1FFFFFFF
CONSTANT: CAN_ERR_MASK 0x1FFFFFFF
STRUCT: can_frame
    { canid u32 }
    { len u8 }
    { __pad u8 }
    { __res0 u8 }
    { len8_dlc u8 }
    { data u8[CAN_MAX_DLEN] } ;


CONSTANT: AF_CAN 29
CONSTANT: CAN_RAW 1
! CONSTANT: CAN_BCM 2
! CONSTANT: CAN_TP16 3
! CONSTANT: CAN_TP20 4
! CONSTANT: CAN_MCNET 5
! CONSTANT: CAN_ISOTP 6
CONSTANT: CAN_J1939 7

STRUCT: tp-addr
    { rx_id u32 }
    { tx_id u32 } ;
STRUCT: j1939-addr
    { name u64 }
    { pgn u32 }
    { addr u8 } ;
UNION-STRUCT: can-addr-struct
    { tp tp-addr }
    { j1939 j1939-addr } ;
STRUCT: sockaddr-can
    { family ushort }
    { index int }
    { can-addr can-addr-struct } ;

CONSTANT: SIOCGSTAMP 0x8906
CONSTANT: SIOCGIFNAME 0x8910
CONSTANT: SIOCGIFINDEX 0x8933

