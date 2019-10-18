! Copyright (C) 2004, 2005 Slava Pestov.
! See http://factor.sf.net/license.txt for BSD license.
IN: compiler
USING: assembler errors generic kernel lists math namespaces
prettyprint sequences strings vectors words ;

! We use a hashtable "compiled-xts" that maps words to
! xt's that are currently being compiled. The commit-xt's word
! sets the xt of each word in the hashtable to the value in the
! hastable.
!
! This has the advantage that we can compile a word before the
! words it depends on and perform a fixup later; among other
! things this enables mutually recursive words.

SYMBOL: compiled-xts

: save-xt ( word -- )
    compiled-offset swap compiled-xts [ acons ] change ;

: commit-xt ( xt word -- )
    dup t "compiled" set-word-prop  set-word-xt ;

: commit-xts ( -- )
    #! We must flush the instruction cache on PowerPC.
    flush-icache
    compiled-xts get [ unswons commit-xt ] each
    compiled-xts off ;

: compiled-xt ( word -- xt )
    dup compiled-xts get assoc [ ] [ word-xt ] ?ifte ;

! Words being compiled are consed onto this list. When a word
! is encountered that has not been previously compiled, it is
! consed onto this list. Compilation stops when the list is
! empty.

SYMBOL: compile-words

! deferred-xts is a list of objects responding to the fixup
! generic.
SYMBOL: deferred-xts

! Some machinery to allow forward references
GENERIC: fixup ( object -- )

TUPLE: relative word where to ;

: just-compiled compiled-offset 4 - ;

C: relative ( word -- )
    over 1 0 rel-word
    [ set-relative-word ] keep
    [ just-compiled swap set-relative-where ] keep
    [ compiled-offset swap set-relative-to ] keep ;

: deferred-xt deferred-xts [ cons ] change ;

: relative ( word -- ) <relative> deferred-xt ;

: relative-fixup ( relative -- addr )
    dup relative-word compiled-xt swap relative-to - ;

M: relative fixup ( relative -- )
    dup relative-fixup swap relative-where set-compiled-cell ;

TUPLE: absolute word where ;

C: absolute ( word -- )
    [ set-absolute-word ] keep
    [ just-compiled swap set-absolute-where ] keep ;

: absolute ( word -- )
    dup 0 0 rel-word <absolute> deferred-xt ;

: >absolute dup absolute-word compiled-xt swap absolute-where ;

M: absolute fixup ( absolute -- )
    >absolute set-compiled-cell ;

! Fixups where the address is inside a bitfield in the
! instruction.
TUPLE: relative-bitfld mask ;

C: relative-bitfld ( word mask -- )
    [ set-relative-bitfld-mask ] keep
    [ >r <relative> r> set-delegate ] keep
    [ just-compiled swap set-relative-to ] keep ;

: relative-24 ( word -- )
    BIN: 11111111111111111111111100 <relative-bitfld>
    deferred-xt ;

: relative-14 ( word -- )
    BIN: 1111111111111100 <relative-bitfld>
    deferred-xt ;

: or-compiled ( n off -- )
    [ compiled-cell bitor ] keep set-compiled-cell ;

M: relative-bitfld fixup
    dup relative-fixup over relative-bitfld-mask bitand
    swap relative-where
    or-compiled ;

! Fixup where the address is split between two PowerPC D-form
! instructions (low 16 bits of each instruction is the literal).
TUPLE: absolute-16/16 ;

C: absolute-16/16 ( word -- )
    [ >r <absolute> r> set-delegate ] keep ;

: fixup-16/16 ( xt where -- )
    >r w>h/h r> tuck 4 - or-compiled or-compiled ;

M: absolute-16/16 fixup ( absolute -- ) >absolute fixup-16/16 ;

: absolute-16/16 ( word -- )
    <absolute-16/16> deferred-xt 0 1 rel-address ;

: compiling? ( word -- ? )
    #! A word that is compiling or already compiled will not be
    #! added to the list of words to be compiled.
    dup compiled? [
        drop t
    ] [
        dup compile-words get member? [
            drop t
        ] [
            compiled-xts get assoc
        ] ifte
    ] ifte ;

: fixup-xts ( -- )
    deferred-xts get [ fixup ] each  deferred-xts off ;

: with-compiler ( quot -- )
    [
        deferred-xts off
        compiled-xts off
        call
        fixup-xts
        commit-xts
    ] with-scope ;

: postpone-word ( word -- )
    dup compiling? [
        drop
    ] [
        compile-words [ unique ] change
    ] ifte ;