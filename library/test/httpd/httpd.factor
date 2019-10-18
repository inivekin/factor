IN: temporary
USE: file-responder
USE: http
USE: httpd
USE: namespaces
USE: io
USE: test
USE: strings
USE: lists

[ "HTTP/1.0 200 OK\nContent-Length: 12\nContent-Type: text/html\n\n" ]
[
    [ "text/html" 12 file-response ] string-out
] unit-test

[
    [
        [[ "X-Spyware-Requested" "yes" ]]
        [[ "User-Agent" "Internet Explorer 0.4alpha" ]]
    ]
]
[
    [ [[ "User-Agent" "Internet Explorer 0.4alpha" ]] ]
    "X-Spyware-Requested: yes" header-line
] unit-test

[ ] [ "404 not found" httpd-error ] unit-test

[ "arg" ] [
    [
        "arg" "default-argument" set
        "" responder-argument
    ] with-scope
] unit-test

[ "inspect/global" ] [ "/inspect/global" trim-/ ] unit-test

[ ] [
    "unit/test" log-responder
] unit-test

[ "index.html" ]
[ "http://www.jedit.org/index.html" url>path ] unit-test

[ "foo/bar" ]
[ "http://www.jedit.org/foo/bar" url>path ] unit-test

[ "" ]
[ "http://www.jedit.org/" url>path ] unit-test

[ "" ]
[ "http://www.jedit.org" url>path ] unit-test

[ "foobar" ]
[ "foobar" secure-path ] unit-test

[ f ]
[ "foobar/../baz" secure-path ] unit-test

[ ] [ "GET ../index.html" parse-request ] unit-test
[ ] [ "POO" parse-request ] unit-test

[ [ [[ "Foo" "Bar" ]] ] ] [ "Foo=Bar" query>alist ] unit-test

[ [ [[ "Foo" "Bar" ]] [[ "Baz" "Quux" ]] ] ]
[ "Foo=Bar&Baz=Quux" query>alist ] unit-test

[ [ [[ "Baz" " " ]] ] ]
[ "Baz=%20" query>alist ] unit-test

[ [ [ "Foo" ] ] ] [ "Foo" query>alist ] unit-test