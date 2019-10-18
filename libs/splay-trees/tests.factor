USING: kernel math namespaces sequences words splay-trees-internals
assocs splay-trees test ;

<splay-tree> "foo" set
all-words [ dup word-name "foo" get set-at ] each
all-words [ word-name "foo" get at drop ] each

: randomize-numeric-splay-tree ( splay-tree -- )
    100 [ drop 100 random swap at drop ] each-with ;

: make-numeric-splay-tree ( n -- splay-tree )
    dup <splay-tree> -rot [ pick set-at ] 2each ;

[ t ] [
    100 make-numeric-splay-tree dup randomize-numeric-splay-tree
    [ [ drop , ] assoc-each ] { } make [ < ] monotonic?
] unit-test

[ 10 ] [ 10 make-numeric-splay-tree keys length ] unit-test
[ 10 ] [ 10 make-numeric-splay-tree keys length ] unit-test

[ f ] [ <splay-tree> f 4 pick set-at 4 swap at ] unit-test

! Ensure that f can be a value
[ t ] [ <splay-tree> f 4 pick set-at 4 swap key? ] unit-test

[
{ { 1 "a" } { 2 "b" } { 3 "c" } { 4 "d" } { 5 "e" } { 6 "f" } }
] [
{
    { 4 "d" } { 5 "e" } { 6 "f" }
    { 1 "a" } { 2 "b" } { 3 "c" }
} >splay-tree >alist
] unit-test
