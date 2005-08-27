! Copyright (C) 2004, 2005 Slava Pestov.
! See http://factor.sf.net/license.txt for BSD license.
IN: generic
USING: kernel kernel-internals ;

DEFER: standard-combination

DEFER: math-combination

: delegate ( object -- delegate )
    dup tuple? [ 3 slot ] [ drop f ] ifte ; inline

: set-delegate ( delegate tuple -- )
    dup tuple? [ 3 set-slot ] [ drop drop ] ifte ; inline
