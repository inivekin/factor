! Copyright (C) 2004, 2005 Slava Pestov.
! See http://factor.sf.net/license.txt for BSD license.
IN: io-internals
USING: alien compiler-backend errors generic hashtables io
kernel kernel-internals lists math parser sequences strings
threads unix-internals vectors ;

! We want namespaces::bind to shadow the bind system call from
! unix-internals
USING: namespaces ;

! This will go elsewhere soon
: byte-bit ( n alien -- byte bit )
    over -5 shift alien-unsigned-4 swap 31 bitand ;

: bit-length ( n -- n ) cell / ceiling ;

: <bit-array> ( n -- array )
    bit-length <byte-array> ;

: bit-nth ( n alien -- ? )
    byte-bit 1 swap shift bitand 0 > ;

: set-bit ( ? byte bit -- byte )
    1 swap shift rot [ bitor ] [ bitnot bitand ] ifte ;

: set-bit-nth ( ? n alien -- )
    [ byte-bit set-bit ] 2keep
    swap -5 shift set-alien-unsigned-4 ;

: clear-bits ( alien len -- )
    bit-length [ 0 -rot set-alien-unsigned-cell ] each-with ;

! Global variables
SYMBOL: read-fdset
SYMBOL: read-tasks
SYMBOL: write-fdset
SYMBOL: write-tasks

! Some general stuff
: file-mode OCT: 0600 ;

: (io-error) err_no strerror throw ;

: check-null ( n -- ) 0 = [ (io-error) ] when ;

: io-error ( n -- ) 0 < [ (io-error) ] when ;

: init-handle ( fd -- ) F_SETFL O_NONBLOCK fcntl io-error ;

! Common delegate of native stream readers and writers
TUPLE: port handle buffer error timeout cutoff output? sbuf eof? ;

: make-buffer ( n -- buffer/f )
    dup 0 > [ <buffer> ] [ drop f ] ifte ;

C: port ( handle buffer -- port )
    [ 0 swap set-port-timeout ] keep
    [ 0 swap set-port-cutoff ] keep
    [ >r make-buffer r> set-delegate ] keep
    [ >r dup init-handle r> set-port-handle ] keep
    80 <sbuf> over set-port-sbuf ;

: touch-port ( port -- )
    ! "touch-port called\n" 14 getenv fwrite 14 getenv fflush
    dup port-timeout dup 0 =
    [ 2drop ] [ millis + swap set-port-cutoff ] ifte ;

M: port set-timeout ( timeout port -- )
    [ set-port-timeout ] keep touch-port ;

: buffered-port 8192 <port> ;

: >port< dup port-handle swap delegate ;

: pending-error ( port -- )
    dup port-error f rot set-port-error throw ;

: report-error ( error port -- )
    [ "Error on fd " % dup port-handle # ": " % swap % ] "" make
    swap set-port-error ;

: defer-error ( port -- ? )
    #! Return t if it is an unrecoverable error.
    err_no dup EAGAIN = over EINTR = or
    [ 2drop f ] [ strerror swap report-error t ] ifte ;

! Associates a port with a list of continuations waiting on the
! port to finish I/O
TUPLE: io-task port callbacks ;
C: io-task ( port -- ) [ set-io-task-port ] keep ;

! Multiplexer
GENERIC: do-io-task ( task -- ? )
GENERIC: task-container ( task -- vector )

: io-task-fd io-task-port port-handle ;

: add-io-task ( callback task -- )
    [ >r unit r> set-io-task-callbacks ] keep
    dup io-task-fd over task-container 2dup hash [
        "Cannot perform multiple I/O ops on the same port" throw
    ] when set-hash ;

: remove-io-task ( task -- )
    dup io-task-fd swap task-container remove-hash ;

: pop-callback ( task -- callback )
    dup io-task-callbacks uncons dup [
        rot set-io-task-callbacks
    ] [
        drop swap remove-io-task
    ] ifte ;

: handle-fd ( task -- )
    dup do-io-task [
        dup io-task-port touch-port pop-callback call
    ] [
        drop
    ] ifte ;

: timeout? ( port -- ? )
    port-cutoff dup 0 = not swap millis < and ;

: handle-fdset ( fdset tasks -- )
    [
        cdr dup io-task-port timeout? [
            dup io-task-port "Timeout" swap report-error
            nip pop-callback call
        ] [
            tuck io-task-fd swap bit-nth
            [ handle-fd ] [ drop ] ifte
        ] ifte
    ] hash-each-with ;

: init-fdset ( fdset tasks -- )
    >r dup FD_SETSIZE clear-bits r>
    [ car t swap rot set-bit-nth ] hash-each-with ;

: init-fdsets ( -- read write except )
    read-fdset get [ read-tasks get init-fdset ] keep
    write-fdset get [ write-tasks get init-fdset ] keep
    f ;

: io-multiplex ( timeout -- )
    >r FD_SETSIZE init-fdsets r> make-timeval select drop
    read-fdset get read-tasks get handle-fdset
    write-fdset get write-tasks get handle-fdset ;

! Readers

: <reader> ( fd -- stream )
    buffered-port <line-reader> ;

: open-read ( path -- fd )
    O_RDONLY file-mode open dup io-error ;

: reader-eof ( reader -- )
    dup port-sbuf empty? [ t swap set-port-eof? ] [ drop ] ifte ;

: (refill) ( port -- n )
    >port< dup buffer-end swap buffer-capacity read ;

: refill ( port -- ? )
    #! Return f if there is a recoverable error
    dup buffer-length 0 = [
        dup (refill)  dup 0 >= [
            swap n>buffer t
        ] [
            drop defer-error
        ] ifte
    ] [
        drop t
    ] ifte ;

! Reading character counts
: read-step ( count reader -- ? )
    dup port-sbuf -rot >r over length - ( remaining) r>
    2dup buffer-length <= [
        buffer> nappend t
    ] [
        buffer>> nip nappend f
    ] ifte ;

: can-read-count? ( count reader -- ? )
    dup pending-error 0 over port-sbuf set-length read-step ;

TUPLE: read-task count ;

C: read-task ( count port -- task )
    [ >r <io-task> r> set-delegate ] keep
    [ set-read-task-count ] keep ;

: >read-task< dup read-task-count swap io-task-port ;

M: read-task do-io-task ( task -- ? )
    >read-task< dup refill [
        dup buffer-empty? [
            reader-eof drop t
        ] [
            read-step
        ] ifte
    ] [
        2drop f
    ] ifte ;

M: read-task task-container drop read-tasks get ;

: wait-to-read ( count port -- )
    2dup can-read-count? [
        [ -rot <read-task> add-io-task stop ] callcc0 
    ] unless 2drop ;

M: port stream-read ( count stream -- string )
    [ wait-to-read ] keep dup port-eof?
    [ drop f ] [ port-sbuf >string ] ifte ;

M: port stream-read1 ( stream -- char/f )
    1 over wait-to-read dup port-eof?
    [ drop f ] [ port-sbuf first ] ifte ;

! Writers

: open-write ( path -- fd )
    O_WRONLY O_CREAT bitor O_TRUNC bitor file-mode open
    dup io-error ;

: <writer> ( fd -- writer )
    buffered-port t over set-port-output? ;

: write-step ( port -- )
    dup >port< dup buffer@ swap buffer-length write dup 0 >= [
        swap buffer-consume
    ] [
        drop defer-error drop
    ] ifte ;

: can-write? ( len writer -- ? )
    #! If the buffer is empty and the string is too long,
    #! extend the buffer.
    dup pending-error
    dup buffer-empty? [
        2drop t
    ] [
        [ buffer-fill + ] keep buffer-capacity <=
    ] ifte ;

TUPLE: write-task ;

C: write-task ( port -- task )
    [ >r <io-task> r> set-delegate ] keep ;

M: write-task do-io-task
    io-task-port dup buffer-length 0 = over port-error or [
        0 swap buffer-reset t
    ] [
        write-step f
    ] ifte ;

M: write-task task-container drop write-tasks get ;

: add-write-io-task ( callback task -- )
    dup io-task-fd write-tasks get hash [
        dup write-task? [
            [ nip io-task-callbacks cons ] keep
            set-io-task-callbacks
        ] [
            drop add-io-task
        ] ifte
    ] [
        add-io-task
    ] ifte* ;

M: port stream-flush ( stream -- )
    dup port-output? [
        [ swap <write-task> add-write-io-task stop ] callcc0
    ] when drop ;

M: port stream-finish ( stream -- ) drop ;

: wait-to-write ( len port -- )
    tuck can-write? [ dup stream-flush ] unless pending-error ;

M: port stream-write1 ( char writer -- )
    1 over wait-to-write ch>buffer ;

M: port stream-format ( string style writer -- )
    nip over length over wait-to-write >buffer ;

M: port stream-close ( stream -- )
    dup stream-flush
    dup port-handle close
    delegate [ buffer-free ] when* ;

! Make a duplex stream for reading/writing a pair of fds

: <fd-stream> ( infd outfd flush? -- stream )
    >r >r <reader> r> <writer> r> <duplex-stream> ;

USE: io

: init-io ( -- )
    #! Should only be called on startup. Calling this at any
    #! other time can have unintended consequences.
    global [
        {{ }} clone read-tasks set
        FD_SETSIZE <bit-array> read-fdset set
        {{ }} clone write-tasks set
        FD_SETSIZE <bit-array> write-fdset set
        0 1 t <fd-stream> stdio set
    ] bind ;