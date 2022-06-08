shared_sources = files('''
    hexmem/hex.c
    hexmem/hex.h
'''.split())

libhex = shared_library('hex', shared_sources, 
                        soversion : '1',
                        version : '1.0.0',
                        include_directories: inc, 
                        install : true)

inc = [inc , include_directories('hexmem')]

#
# Install 
#
install_headers('hexmem/hex.h')

