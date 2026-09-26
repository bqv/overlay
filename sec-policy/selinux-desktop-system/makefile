# The selinux-policy-2 eclass installs this package's .if files into
# /usr/share/selinux/mcs/include/3rd_party, and that directory is on the m4
# include path. Building while those copies are still installed defines every
# interface twice, and m4 fails the build with "duplicate definition of ...".
# Clear this package's own installed copies first - the build reinstalls them.
HEADERS = /usr/share/selinux/mcs/include/3rd_party

all:
	ebuild *.ebuild manifest

compile:
	-rm -f $(HEADERS)/desktop.system*.if
	ebuild *.ebuild manifest clean compile

merge:
	-rm -f $(HEADERS)/desktop.system*.if
	ebuild *.ebuild manifest clean merge
