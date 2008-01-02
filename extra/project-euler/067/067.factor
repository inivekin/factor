! Copyright (c) 2007 Samuel Tardieu, Aaron Schaefer.
! See http://factorcode.org/license.txt for BSD license.
USING: io io.files kernel math.parser namespaces project-euler.018
    project-euler.common sequences splitting system vocabs ;
IN: project-euler.067

! http://projecteuler.net/index.php?section=problems&id=67

! DESCRIPTION
! -----------

! By starting at the top of the triangle below and moving to adjacent numbers
! on the row below, the maximum total from top to bottom is 23.

!        3
!       7 5
!      2 4 6
!     8 5 9 3

! That is, 3 + 7 + 4 + 9 = 23.

! Find the maximum total from top to bottom in triangle.txt (right click and
! 'Save Link/Target As...'), a 15K text file containing a triangle with
! one-hundred rows.

! NOTE: This is a much more difficult version of Problem 18. It is not possible
! to try every route to solve this problem, as there are 2^99 altogether! If you
! could check one trillion (10^12) routes every second it would take over twenty
! billion years to check them all. There is an efficient algorithm to solve it. ;o)


! SOLUTION
! --------

! Propagate from bottom to top the longest cumulative path as is done in
! problem 18.

<PRIVATE

: pyramid ( -- seq )
    "resource:extra/project-euler/067/triangle.txt" ?resource-path
    <file-reader> lines [ " " split [ string>number ] map ] map ;

PRIVATE>

: euler067 ( -- answer )
    pyramid propagate-all first first ;

! [ euler067 ] 100 ave-time
! 18 ms run / 0 ms GC time


! ALTERNATE SOLUTIONS
! -------------------

<PRIVATE

: (source-067a) ( -- path )
    [
        "project-euler.067" vocab-root ?resource-path %
        os "windows" = [
            "\\project-euler\\067\\triangle.txt" %
        ] [
            "/project-euler/067/triangle.txt" %
        ] if
    ] "" make ;

: source-067a ( -- triangle )
    (source-067a) <file-reader> lines [ " " split [ string>number ] map ] map ;

PRIVATE>

: euler067a ( -- answer )
    source-067a max-path ;

! [ euler067a ] 100 ave-time
! 15 ms run / 0 ms GC ave time - 100 trials

! source-067a [ max-path ] curry 100 ave-time
! 3 ms run / 0 ms GC ave time - 100 trials

MAIN: euler067a
