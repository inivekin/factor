USING: accessors alien alien.c-types alien.strings arrays assocs
byte-arrays calendar classes.struct combinators.smart
concurrency.conditions concurrency.flags continuations fonts
formatting io io.backend.unix io.encodings.utf8 io.sockets
io.sockets.private io.sockets.unix io.streams.string io.timeouts
kernel math math.bitwise math.parser models models.arrow
namespaces sequences socketcan.types strings threads ui
ui.gadgets ui.gadgets.labels ui.gadgets.search-tables
ui.gadgets.tables ui.gadgets.tracks ui.theme ui.tools.common
unix.ffi unix.ffi.linux unix.time unix.types ;
FROM: models => change-model ;
IN: socketcan

TUPLE: socketcan { port maybe{ integer } read-only initial: f } ;
TUPLE: rawcan  < socketcan { channel maybe{ string } read-only initial: f } ;

! because `receive` doesn't produce the port/file descriptor after the call, the fd is accesible in this variable
! currently require fd after receive for some ioctls as receive uses recvfrom (would usually use recvmsg with can stuff to avoid that)
SYMBOL: canbus

C: <rawcan> rawcan
M: rawcan protocol-family drop AF_CAN ;
M: rawcan protocol drop CAN_RAW ;
M: rawcan remote>handle
    [ protocol-family SOCK_RAW ] [ protocol ] bi socket-fd
    [ init-client-socket ] [ ?bind-client ] [ ] tri ;
M: rawcan sockaddr-size drop sockaddr-can heap-size ;

TUPLE: canframe id data { extended? initial: f } { remote? initial: f } { error? initial: f } { timestamp initial: f } ;
C: <canframe> canframe

: <std-canframe> ( id bytes -- canframe ) f f f f <canframe> ;
: <ext-canframe> ( id bytes -- canframe ) t f f f <canframe> ;


: check-flag ( n flag -- ? ) bitand zero? not ;
: extended-frame-id? ( id -- ? ) CAN_EFF_FLAG check-flag ;
: remote-frame-id? ( id -- ? ) CAN_RTR_FLAG check-flag ;
: error-frame-id? ( id -- ? ) CAN_ERR_FLAG check-flag ;
: (parse-canframe) ( struct -- canframe )
    [ canid>> dup extended-frame-id? [ CAN_EFF_MASK bitand ] [ CAN_SFF_MASK mask ] if ]
    [ [ data>> >byte-array ] [ len>> ] bi head ]
    [ canid>> [ extended-frame-id? ] [ remote-frame-id? ] [ error-frame-id? ] tri ] tri
    f <canframe> ;
: set-id-flag ( id ? flag -- 'id ) swap [ bitor ] [ unmask ] if ;
: set-id-flags ( canframe -- id )
    dup id>> swap
    [ extended?>> CAN_EFF_FLAG set-id-flag ]
    [ remote?>> CAN_RTR_FLAG set-id-flag ]
    [ error?>> CAN_ERR_FLAG set-id-flag ] tri ;
: check-dlc-limit ( n -- )
    dup CAN_MAX_DLEN > [ number>string "Too many bytes for frame: " prepend throw ] [ drop ] if ;
: pack-canframe ( canframe -- struct )
    [ set-id-flags ]
    [ data>> [ length dup check-dlc-limit ] keep >byte-array ] bi
    [ 0 0 0 ] dip
    can_frame boa ;
: unique-str-id ( canframe -- str ) set-id-flags "%08X" sprintf ;

: ioctl-throw-check ( fd request args -- args )
    [ >c-ptr ioctl [ number>string "failed ioctl: " prepend throw ] unless-zero ] keep ;

: channel>index ( addrspec -- n )
    dup channel>>
    [
        length IFNAMSIZ > [ "socketcan interface name too long" throw ] when
        [
            canbus get [ nip handle>> fd>> ] [ remote>handle handle-fd ] if*
            SIOCGIFINDEX ] [ channel>> utf8 string>alien ifru new ifreq boa ] bi
        ioctl-throw-check ifr_ifru>> ivalue>>
    ]
    [ drop 0 ] if*
    ;

M: rawcan make-sockaddr
    sockaddr-can new 
    AF_CAN >>family
    swap channel>index >>index
    ;

: addrspec>socketcan_name ( addrspec index -- 'addrspec )
    [ drop f ]
    [
        [
            canbus get [ nip handle>> fd>> ] [ remote>handle handle-fd ] if*
            SIOCGIFNAME ] [ ifreq new [ ifr_ifru>> ivalue<< ] keep ] bi*
        ioctl-throw-check ifr_ifrn>> ifrn_name>> utf8 alien>string
    ] if-zero
    [ f ] dip <rawcan> ;
M: rawcan parse-sockaddr swap index>> addrspec>socketcan_name ;
M: rawcan empty-sockaddr drop sockaddr-can new ;

: last-recv-timestamp ( addrspec -- timestamp )
    canbus get [ nip handle>> fd>> ] [ remote>handle handle-fd ] if* SIOCGSTAMP timeval new
    ioctl-throw-check [ sec>> ] [ usec>> 1000000 /f + ] bi duration new swap >>second unix-1970 swap time+ ;

: parse-canframe ( bytes -- canframe )
    >c-ptr can_frame memory>struct (parse-canframe) ;
: receive-canmsg ( datagram -- canframe addrspec )
    receive [ parse-canframe ] [ [
    last-recv-timestamp
    >>timestamp ] keep ] bi* ;

: send-canmsg ( canframe addrspec -- )
    [ pack-canframe >c-ptr ]
    [ dup <raw> ] bi* send ;

: (print-channel) ( addrspec -- ) channel>> "%s " printf ;
: (print-id) ( canframe -- )
    [ id>> ] [ extended?>> ] bi [ "%08X#" printf ] [ "      %03X#" printf ] if ;
: (print-data) ( canframe -- ) data>> [ "%02X" printf ] each ;
: (print-candump-frame) ( addrspec canframe -- )
    [ (print-channel) ] [ [ (print-id) ] [ (print-data) ] bi ] bi* ;
: print-candump-frame ( canframe addrspec timestamp -- )
    "(%.6f) " printf swap (print-candump-frame) ;
: enter-pressed? ( -- )
    readln drop ;
: input-flag-raised? ( flag -- ? )
    [ 0 seconds wait-for-flag-timeout f ] [ timed-out-error? [ t ] [ f ] if nip ] recover ;
: (candump) ( datagram ts flag -- )
    '[ [
      [ _ receive-canmsg now _ time- duration>seconds print-candump-frame nl flush ]
      [ dup io-timeout? [ rethrow ] unless drop ] recover
      _ input-flag-raised?
    ] loop ] in-thread ;
: candump ( datagram -- )
    1 seconds over set-timeout
    now <flag> [ (candump) ] keep
    enter-pressed? raise-flag ;


TUPLE: canviewer-row addrspec canframe dt count ;
C: <canviewer-row> canviewer-row
: with-canbus ( channel quot: ( datagram -- ) -- )
    [ f swap <rawcan> <raw> canbus ] dip '[ canbus get @ ] with-variable ; inline

: candump-any ( -- )
    "bus" get [ candump ] with-canbus ;

SINGLETON: cantable-renderer
INITIALIZED-SYMBOL: updating-id-list [ H{ } clone <model> ]
: add-to-id-list ( addrspec canframe -- ) 
    [ duration new 1 <canviewer-row> <model> ] keep unique-str-id updating-id-list get [ set-at ] change-model* ;
: update-id-list ( canframe addrspec -- )
    over unique-str-id updating-id-list get [ at
        [ [ dup canframe>> timestamp>> dup [ drop unix-1970 ] unless [ [ addrspec<< ] [ canframe<< ] [ ] tri ] dip over canframe>> timestamp>> swap time- >>dt [ 1 + ] change-count ] change-model ]
        [ swap add-to-id-list ] if*
    ] change-model*
    ;
M: cantable-renderer filled-column drop 6 ;
M: cantable-renderer column-titles drop { "time" "dt" "count" "bus" "dlc" "id" "data" } ;
M: cantable-renderer row-columns drop 
    updating-id-list get value>> at value>>
    {
      [ canframe>> timestamp>> [ timestamp>unix-time >float "%.6f" sprintf ] [ "0.0" ] if* ]
      [ dt>> duration>seconds >float "%.6f" sprintf ]
      [ count>> number>string ] 
      [ addrspec>> channel>> ]
      [ canframe>> data>> length number>string ] 
      [ [ canframe>> (print-id) ] with-string-writer ] 
      [ canframe>> data>> [ "%02X" sprintf ] { } map-as " " join ] 
    } { } cleave>sequence ;
M: cantable-renderer row-color 2drop text-color ;
M: cantable-renderer row-value drop updating-id-list get value>> at value>> canframe>> [ (print-id) ] with-string-writer ;

: <cantable> ( channel -- table )
    '[
        _ [ '[ _ receive-canmsg update-id-list t ] loop ] with-canbus
    ] in-thread
    updating-id-list get [ keys ] <arrow> cantable-renderer [ ] <search-table> white-interior
    dup table>> 5 >>gap f >>takes-focus? default-monospace-font-name <font> >>font drop
    ;
    
MAIN: candump-any
