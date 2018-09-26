'''
Quick AppArmor-style sandbox profile template generator for Pyronia-secured
applications.

Generates an application-level profile to be loaded via apparmor_parser,
and a library-level profile to be loaded as part of the app registration
step during the Pyronia initialization.

The generator includes all required default resources for all
Pyronia-secured applications, and template resource access rules
for libraries to be filled in by the developers. The second generated
profile includes a template per-library resource list to be filled in by
the developer. To enable a library's access to desired resources, the
resources specified in the library profile must mirror the non-default
resources specified in the application-wide profile. The access permissions
specified for non-default resources in the application-wide profile
will be granted to all libraries specifying access to those same resrouces.

Author: Marcela S. Melara
'''
import os
import sys

# TODO: use single list of defaults, and generate dynamically

def writeln(f, to_write):
    f.write(to_write+'\n')

# adapted from: github.com/kantai/passe-framework-prototype/blob/master/django/analysis/persisted.py
def create_apparmor_prof(prof_path, app):
    z = open(prof_path, 'w')
    writeln(z, app+" {")
    writeln(z, "# these need to be included by default")
    writeln(z, "/etc/ld.so.cache r,")
    writeln(z, "/lib/x86_64-linux-gnu/libc-2.23.so rm,")
    writeln(z, "/lib/x86_64-linux-gnu/libpyronia.so rm,")
    writeln(z, "/lib/x86_64-linux-gnu/libsmv.so rm,")
    writeln(z, "/lib/x86_64-linux-gnu/libpthread-2.23.so rm,")
    writeln(z, "/lib/x86_64-linux-gnu/libnl-genl-3.so.200.22.0 rm,")
    writeln(z, "/lib/x86_64-linux-gnu/libnl-3.so.200.22.0 rm,")
    writeln(z, "/lib/x86_64-linux-gnu/libm-2.23.so rm,")
    writeln(z, "/lib/x86_64-linux-gnu/libgcc_s.so.1 rm,")
    writeln(z, "/proc/*/net/psched r,")
    writeln(z, "/dev/pts/* r,")
    writeln(z, prof_path+"-lib.prof r,")
    writeln(z, "")
    writeln(z, "# TODO: replace these with YOUR resource access rules")
    writeln(z, "<file1> <perms>,")
    writeln(z, "<file2> <perms>,")
    writeln(z, "network inet,")
    writeln(z, "}")
    z.close()

def create_lib_prof(prof_path):
    z = open(prof_path, 'w')
    writeln(z, "d /etc/ld.so.cache,")
    writeln(z, "d /lib/x86_64-linux-gnu/libc-2.23.so,")
    writeln(z, "d /lib/x86_64-linux-gnu/libpyronia.so,")
    writeln(z, "d /lib/x86_64-linux-gnu/libsmv.so,")
    writeln(z, "d /lib/x86_64-linux-gnu/libpthread-2.23.so,")
    writeln(z, "d /lib/x86_64-linux-gnu/libnl-genl-3.so.200.22.0,")
    writeln(z, "d /lib/x86_64-linux-gnu/libnl-3.so.200.22.0,")
    writeln(z, "d /lib/x86_64-linux-gnu/libm-2.23.so,")
    writeln(z, "d /lib/x86_64-linux-gnu/libgcc_s.so.1,")
    writeln(z, "d /proc/*/net/psched,")
    writeln(z, "d /dev/pts/*,")
    writeln(z, "")
    writeln(z, "<lib1> <file1>,")
    writeln(z, "<lib2> <file1>,")
    writeln(z, "<lib2> <file2,")
    writeln(z, "<lib1> network <IP address>,")
    writeln(z, "<lib3> network <IP address>,")
    z.close()

if __name__ == '__main__':
    # expect the absolute path to the application to be confined,
    # and the destination for the generated profile templates.
    if len(sys.argv) != 3:
        print('Usage: python generate-pyr-policy-template.py <abs app path> <dir>')
        sys.exit(0)

    # parse the command-line args
    app_path = os.path.normpath(sys.argv[1])
    prof_dest_dir = os.path.normpath(sys.argv[2])

    # generate the app-wide profile name
    # names requires the absolute path of the application to be "."-separated
    app_prof_file = ".".join(app_path.lstrip(os.path.sep).split(os.path.sep))
    create_apparmor_prof(prof_dest_dir+"/"+app_prof_file, app_path)
    create_lib_prof(prof_dest_dir+"/"+app_prof_file+"-lib.prof")
