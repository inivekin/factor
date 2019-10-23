! Copyright (C) 2006 Doug Coleman
! See http://factorcode.org/license.txt for BSD license.
USING: checksums io.binary kernel math sequences
sequences.private ;
IN: checksums.crc32

CONSTANT: crc32-polynomial 0xedb88320

CONSTANT: crc32-table V{ }

256 <iota> [
    8 [
        [ 2/ ] [ even? ] bi [ crc32-polynomial bitxor ] unless
    ] times
] map 0 crc32-table copy

: (crc32) ( crc ch -- crc )
    dupd bitxor
    mask-byte crc32-table nth-unsafe
    swap -8 shift bitxor ; inline

SINGLETON: crc32

INSTANCE: crc32 checksum

: init-crc32 ( input checksum -- x y input )
    drop [ 0xffffffff dup ] dip ; inline

: finish-crc32 ( x y -- bytes )
    bitxor 4 >be ; inline

M: crc32 checksum-bytes
    init-crc32
    [ (crc32) ] each
    finish-crc32 ; inline

M: crc32 checksum-lines
    init-crc32
    [ [ (crc32) ] each char: \n (crc32) ] each
    finish-crc32 ; inline