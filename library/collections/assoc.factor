! Copyright (C) 2004, 2005 Slava Pestov.
! See http://factor.sf.net/license.txt for BSD license.
IN: lists USING: kernel sequences ;

: assoc* ( key alist -- [[ key value ]] )
    #! Look up a key/value pair.
    [ car = ] find-with nip ;

: assoc ( key alist -- value ) assoc* cdr ;

: remove-assoc ( key alist -- alist )
    #! Remove all key/value pairs with this key.
    [ car = not ] subset-with ;

: acons ( value key alist -- alist )
    #! Adds the key/value pair to the alist. Existing pairs with
    #! this key are not removed; the new pair simply shadows
    #! existing pairs.
    >r swons r> cons ;

: set-assoc ( value key alist -- alist )
    #! Adds the key/value pair to the alist.
    dupd remove-assoc acons ;

: assoc-apply ( value-alist quot-alist -- )
    #! Looks up the key of each pair in the first list in the
    #! second list to produce a quotation. The quotation is
    #! applied to the value of the pair. If there is no
    #! corresponding quotation, the value is popped off the
    #! stack.
    swap [
        unswons rot assoc* dup [ cdr call ] [ 2drop ] ifte
    ] each-with ;