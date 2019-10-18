! Copyright (C) 2004, 2005 Slava Pestov.
! See http://factor.sf.net/license.txt for BSD license.
IN: inference
USING: generic hashtables kernel lists math namespaces sequences
vectors words ;

! Method inlining optimization

GENERIC: dispatching-values ( node word -- seq )

M: object dispatching-values 2drop { } ;

M: simple-generic dispatching-values drop node-in-d peek 1vector ;

M: 2generic dispatching-values drop node-in-d 2 swap tail* ;

: node-classes* ( node seq -- seq )
    >r node-classes r>
    [ swap hash [ object ] unless* ] map-with ;

: dispatching-classes ( node -- seq )
    dup dup node-param dispatching-values node-classes* ;

: already-inlined? ( node -- ? )
    #! Was this node inlined from definition of 'word'?
    dup node-param swap node-history memq? ;

: inlining-class ( #call -- class )
    #! If the generic dispatch can be eliminated, return the
    #! class of the method that will always be invoked here.
    dup already-inlined? [
        drop f
    ] [
        dup dispatching-classes dup empty? [
            2drop f
        ] [
            dup [ = ] monotonic? [
                first swap node-param order min-class
            ] [
                2drop f
            ] ifte
        ] ifte
    ] ifte ;

: will-inline ( node -- quot )
    dup inlining-class swap node-param "methods" word-prop hash ;

: method-dataflow ( node -- dataflow )
    dup will-inline swap node-in-d dataflow-with
    dup solve-recursion ;

: inline-method ( node -- node )
    #! We set the #call node's param to f so that it gets killed
    #! later.
    dup method-dataflow
    [ >r node-param r> remember-node ] 2keep
    [ subst-node ] keep ;

: related? ( actual testing -- ? )
    #! If actual is a subset of testing or if the two classes
    #! are disjoint, return t.
    2dup class< >r classes-intersect? not r> or ;

: optimize-predicate? ( #call -- ? )
    dup node-param "predicating" word-prop dup [
        >r dup node-in-d node-classes* first r> related?
    ] [
        2drop f
    ] ifte ;

: optimize-predicate ( #call -- node )
    dup node-param "predicating" word-prop >r
    dup dup node-in-d node-classes* first r> class<
    1vector inline-literals ;