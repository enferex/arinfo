arinfo: Hash and list the contents of an archive (.a) file.
===========================================================
arinfo displays information about the objects within an archive (.a) file.
Archive files are commonly used as static libraries.  The main feature of
arinfo is that it produces an md5 hash of the contents for the objects files
within the archive.

arinfo can be used to find .a files that have duplicate objects across other
.a files.  The output from arinfo is .csv (See the -h option for the header).

The GNU 'ar' utility is used for building .a files, and has a very helpful
listing option (`ar -t <file>`); however, that does not list the hash value for
the individual objects within the archive.

arinfo also lists any unecpected data at the end of a .a file.  For instance,
if the last object in the archive has a size that does not reach the end of the
file, then there is some unexpected space between the end of the last object
and the file.  That space is what I call 'tail padding'; however, it's unclear
what that data might be.  That unexpected data could be the result of just
reading the .a file incorrectly.

Caveats
-------
If an object's filename has unexpected/non-printable characters, then arinfo
will only display a truncated representation of that filename.

Building
--------
1. Invoke `make` to build this puppy.

Dependencies
------------
OpenSSL: https://openssl.org

References
----------
* https://en.wikipedia.org/wiki/Ar_(Unix)

Contact
-------
Matt Davis: https://github.com/enferex
