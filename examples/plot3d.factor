! 3d surface plotter.
!
! To run this code, bootstrap Factor like so:
!
! ./f boot.image.le32
!     -libraries:sdl:name=libSDL.so
!     -libraries:sdl-gfx:name=libSDL_gfx.so
!
! (But all on one line)
!
! Then, start Factor as usual (./f factor.image) and enter this
! at the listener:
!
! "contrib/gl/load.factor" run-file
! "examples/plot3d.factor" run-file

IN: plot3d
USING: alien compiler errors gl kernel lists math namespaces
prettyprint sdl sequences vectors ;

: display-list 1 ;

: matrix-get ( i j matrix -- ) swapd nth nth ;

: plot-vertex ( matrix i j -- )
    rot matrix-get 3unseq glVertex3f ;

: plot-face ( matrix i j -- face )
    GL_QUADS glBegin
       [ rot matrix-get ] 3keep
       [ 1 + rot matrix-get v- ] 3keep
       [ rot matrix-get ] 3keep
       [ >r 1 + r> rot matrix-get v- cross normalize 3unseq glNormal3f ] 3keep
       [ plot-vertex ] 3keep
       [ 1 + plot-vertex ] 3keep
       [ >r 1 + r> 1 + plot-vertex ] 3keep
       >r 1 + r> plot-vertex
    glEnd ;

: 2repeat ( i j quot -- | quot: i j -- i j )
    rot [
        rot [ [ rot dup slip -rot ] repeat ] keep -rot
    ] repeat 2drop ; inline

: plot-faces ( points -- )
    dup length 1 - over first length 1 - [
        3dup plot-face
    ] 2repeat drop ;

SYMBOL: theta

: plot-axes ( -- )
    GL_LIGHTING glDisable
    1.0 1.0 1.0 glColor3f
    GL_LINES glBegin
        0 0 0 glVertex3f
        1 0 0 glVertex3f
        0 0 0 glVertex3f
        -1 0 0 glVertex3f
        0 0 0 glVertex3f
        0 1 0 glVertex3f
        0 0 0 glVertex3f
        0 -1 0 glVertex3f
        0 0 0 glVertex3f
        0 0 1 glVertex3f
        0 0 0 glVertex3f
        0 0 -1 glVertex3f
    glEnd
    GL_LIGHTING glEnable ;

: i/j>x/y ( i j -- x y )
    swap 15 - 30 / swap 15 - 30 / ;

: max-z ( seq -- z )
    0.1 [ third max ] reduce ;

: min-z ( seq -- z )
    -0.1 [ third min ] reduce ;

: normalize-points ( seq -- )
    dup min-z over [ over >r 3unseq r> - 3vector ] nmap drop
    dup max-z swap [ over >r 3unseq r> / 3vector ] nmap drop ;

: valuate-points ( quot -- matrix )
    30 [
        ( quot i )
        30 [
            ( quot i j )
            [ 3dup i/j>x/y rot call ] 2keep i/j>x/y rot 3vector nip
        ] map 2nip
    ] map-with ; inline

: make-plot
    [ rect> real ] valuate-points
    dup [ normalize-points ] each
    display-list GL_COMPILE glNewList
        plot-faces
        plot-axes
    glEndList ;

: flags
    SDL_OPENGL SDL_RESIZABLE bitor SDL_HWSURFACE bitor SDL_DOUBLEBUF bitor ;

: fov          60.0 ; inline
: near         0.1 ; inline
: far          100.0 ; inline

: >float-array ( seq -- float-array )
    dup length <float-array> over length [
        [ tuck >r >r swap nth r> r> swap set-float-nth ] 3keep
    ] repeat nip ;

: init-gl
    GL_PROJECTION glMatrixMode
    GL_DEPTH_TEST glEnable
    GL_LIGHTING glEnable
    GL_LIGHT0 glEnable
    GL_LIGHT1 glEnable
    glLoadIdentity
    fov width get height get /f near far gluPerspective
    GL_LIGHT0 GL_POSITION [ 1.0 1.0 -2.0 1.0 ] >float-array glLightfv
    GL_LIGHT0 GL_DIFFUSE [ 1.0 0.5 0.0 1.0 ] >float-array glLightfv
    GL_LIGHT0 GL_SPECULAR [ 1.0 0.5 1.0 1.0 ] >float-array glLightfv
    GL_LIGHT0 GL_AMBIENT [ 1.0 1.0 0.5 1.0 ] >float-array glLightfv
    GL_LIGHT1 GL_POSITION [ 1.0 3.0 2.0 -1.0 ] >float-array glLightfv
    GL_LIGHT1 GL_DIFFUSE [ 1.0 0.5 0.3 1.0 ] >float-array glLightfv
    GL_LIGHT1 GL_SPECULAR [ 1.0 1.0 0.5 1.0 ] >float-array glLightfv
    GL_LIGHT1 GL_AMBIENT [ 0.0 0.0 1.0 1.0 ] >float-array glLightfv
    GL_MODELVIEW glMatrixMode
    glLoadIdentity
    GL_SMOOTH glShadeModel
    
    0.0 0.0 0.0 0.0 glClearColor
    1.0 0.0 0.0 glColor3f ;

: render ( -- )
    GL_COLOR_BUFFER_BIT GL_DEPTH_BUFFER_BIT bitor glClear
    GL_MODELVIEW glMatrixMode
    glLoadIdentity
    0.0 -0.5 -1.5 glTranslatef
    -45 1 0 0 glRotatef
    theta get 0 0 1 glRotatef
    display-list glCallList
    SDL_GL_SwapBuffers ;

: event-loop ( event -- )
    theta [ 1 + ] change
    render
    dup SDL_PollEvent [
        dup event-type SDL_QUIT = [
            drop
        ] [
            event-loop
        ] ifte
    ] [
        event-loop
    ] ifte ;

: plot3d ( -- )
    1024 768 16 flags [
        init-gl
        0 theta set
        make-plot
        <event> event-loop SDL_Quit
    ] with-screen ;

plot3d