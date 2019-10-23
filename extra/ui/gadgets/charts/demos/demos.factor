! Copyright (C) 2017 Alexander Ilin.
! See http://factorcode.org/license.txt for BSD license.
USING: accessors arrays colors.constants
combinators.smart.syntax kernel literals locals math
math.constants math.functions sequences ui ui.gadgets
ui.gadgets.charts ui.gadgets.charts.axes ui.gadgets.charts.lines ;
IN: ui.gadgets.charts.demos

<<
CONSTANT: -pi 1[ pi neg ]
>>

: sine-wave ( steps -- seq )
    [ <iota> ] keep
    pi 2 * swap / [ * pi - dup sin 2array ] curry map
    array[ pi 1[ pi sin ] ] suffix ;

: cosine-wave ( steps -- seq )
    [ <iota> ] keep
    pi 2 * swap / [ * pi - dup cos 2array ] curry map
    array[ pi 1[ pi cos ] ] suffix ;

<PRIVATE

:: (chart-demo) ( n -- )
    chart new array[ array[ -pi pi ] { -1 1 } ] >>axes
    line new color: blue >>color n sine-wave >>data add-gadget
    line new color: red >>color n cosine-wave >>data add-gadget
    vertical-axis new add-gadget
    horizontal-axis new add-gadget
    "Chart" open-window ;

PRIVATE>

: chart-demo ( -- ) 40 (chart-demo) ;

MAIN: chart-demo

! chart new line new color: blue >>color { { 0 100 } { 100 0 } { 100 50 } { 150 50 } { 200 100 } } >>data add-gadget "Chart" open-window