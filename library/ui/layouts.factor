! Copyright (C) 2005 Slava Pestov.
! See http://factor.sf.net/license.txt for BSD license.
IN: gadgets-layouts
USING: errors gadgets generic hashtables kernel lists math
matrices namespaces sdl sequences ;

: relayout ( gadget -- )
    #! Relayout and redraw a gadget and its parent before the
    #! next iteration of the event loop.
    dup gadget-relayout? [
        drop
    ] [
        dup invalidate
        dup gadget-root?
        [ add-invalid ]
        [ gadget-parent [ relayout ] when* ] ifte
    ] ifte ;

: set-gadget-dim ( dim gadget -- )
    2dup rect-dim = [
        2drop
    ] [
        [ set-rect-dim ] keep dup add-invalid invalidate
    ] ifte ;

GENERIC: pref-dim ( gadget -- dim )

M: gadget pref-dim rect-dim ;

GENERIC: layout* ( gadget -- )

M: gadget layout* drop ;

: prefer ( gadget -- ) dup pref-dim swap set-gadget-dim ;

: layout ( gadget -- )
    #! Set the gadget's width and height to its preferred width
    #! and height. The gadget's children are laid out first.
    #! Note that nothing is done if the gadget does not need to
    #! be laid out.
    dup gadget-relayout? [
        f over set-gadget-relayout?
        dup layout*
        gadget-children [ layout ] each
    ] [
        drop
    ] ifte ;

TUPLE: pack align fill gap vector ;

: pref-dims ( gadget -- list )
    gadget-children [ pref-dim ] map ;

: orient ( gadget seq1 seq2 -- seq )
    >r >r pack-vector r> r> [ pick set-axis ] 2map nip ;

: packed-dim-2 ( gadget sizes -- list )
    [ over rect-dim over v- rot pack-fill v*n v+ ] map-with ;

: packed-dims ( gadget sizes -- seq )
    2dup packed-dim-2 swap orient ;

: packed-loc-1 ( gadget sizes -- seq )
    { 0 0 0 } [ v+ over pack-gap v+ ] accumulate nip ;

: packed-loc-2 ( gadget sizes -- seq )
    [ >r dup pack-align swap rect-dim r> v- n*v ] map-with ;

: packed-locs ( gadget sizes -- seq )
    2dup packed-loc-1 >r dupd packed-loc-2 r> orient ;

: packed-layout ( gadget sizes -- )
    over gadget-children
    >r dupd packed-dims r> 2dup [ set-gadget-dim ] 2each
    >r packed-locs r> [ set-rect-loc ] 2each ;

C: pack ( vector -- pack )
    #! gap: between each child.
    #! fill: 0 leaves default width, 1 fills to pack width.
    #! align: 0 left, 1/2 center, 1 right.
    [ set-pack-vector ] keep
    <gadget> over set-delegate
    0 over set-pack-align
    0 over set-pack-fill
    { 0 0 0 } over set-pack-gap ;

: <pile> ( -- pack ) { 0 1 0 } <pack> ;

: <shelf> ( -- pack ) { 1 0 0 } <pack> ;

M: pack pref-dim ( pack -- dim )
    [
        [
            pref-dims
            [ { 0 0 0 } [ vmax ] reduce ] keep
            [ { 0 0 0 } [ v+ ] reduce ] keep length 1 - 0 max
        ] keep pack-gap n*v v+
    ] keep pack-vector set-axis ;

M: pack layout* ( pack -- ) dup pref-dims packed-layout ;

: fast-children-on ( dim axis gadgets -- i )
    swapd [ rect-loc origin get v+ v- over v. ] binsearch nip ;

M: pack children-on ( rect pack -- list )
    dup pack-vector swap gadget-children [
        3dup
        >r >r dup rect-loc swap rect-dim v+ r> r> fast-children-on 1 +
        >r
        >r >r rect-loc r> r> fast-children-on 0 max
        r>
    ] keep <slice> ;

TUPLE: stack ;

C: stack ( -- gadget )
    #! A stack lays out all its children on top of each other.
    { 0 0 1 } <pack> over set-delegate
    1 over set-pack-fill ;

M: stack children-on ( point stack -- gadget )
    nip gadget-children ;