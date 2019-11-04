#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include <iomanip>
#include <stdexcept>
#include <string>

#include <gtest/gtest.h>

// the errno the sandbox should set when denying function calls
const int ESBX = EACCES;

std::runtime_error rtef(const char *fmt, ...) {
    char *errcstr;
    va_list ap;
    va_start(ap, fmt);
    vasprintf(&errcstr, fmt, ap);
    va_end(ap);
    std::runtime_error r(errcstr);
    free(errcstr);
    return r;
}

static void *findfunc(const char *name) {
    static void *libc = 0;
    if (!libc) {
        libc = dlopen("libc.so.6", RTLD_LAZY);
        if (!libc) {
            throw rtef("dlopen(libc.so.6) failed: %s", dlerror());
        }
    }
    void *f = dlsym(libc, name);
    if (!f) {
        throw rtef("dlsym(%s) failed: %s", name, dlerror());
    }
    return f;
}

#define libc(name) reinterpret_cast<decltype(&name)>(findfunc(#name))
#define libc_decl(name) decltype(&name) libc_##name = libc(name)

libc_decl(getcwd);
libc_decl(unlink);
libc_decl(open);
libc_decl(write);
libc_decl(close);
libc_decl(symlink);
libc_decl(chdir);
libc_decl(mkdir);
libc_decl(rmdir);
libc_decl(remove);

#define EXPECT_MAYBE_ERRNO(e, op)                                                           \
    do {                                                                                    \
        int oerrno = errno;                                                                 \
        auto ret = op;                                                                      \
        EXPECT_TRUE(ret == 0 or e == errno)                                                 \
            << #op "\n"                                                                     \
            << "expected retval / errno\n"                                                  \
            << "  one of " << std::setw(6) << 0 << " / " << std::setw(5) << e << ": "       \
            << strerror(e) << "\n"                                                          \
            << "     got " << std::setw(6) << ret << " / " << std::setw(5) << errno << ": " \
            << strerror(errno);                                                             \
        errno = oerrno;                                                                     \
    } while (0)

class SandboxTest : public ::testing::Test {
  protected:
    char basedir[PATH_MAX];

    void SetUp() override {
        ASSERT_TRUE(libc_getcwd(basedir, PATH_MAX));
        int fd;
        ASSERT_NE(-1, fd = libc_open("f0", O_WRONLY | O_CREAT | O_EXCL, 0644));
        ASSERT_EQ(2, libc_write(fd, "a\n", 2));
        ASSERT_EQ(0, libc_close(fd));

        ASSERT_EQ(0, libc_mkdir("dempty", 0755));
        ASSERT_EQ(0, libc_mkdir("dhasfile", 0755));

        ASSERT_NE(-1, fd = libc_open("dhasfile/f1", O_WRONLY | O_CREAT | O_EXCL,
                                     0644));
        ASSERT_EQ(2, libc_write(fd, "b\n", 2));
        ASSERT_EQ(0, libc_close(fd));

        ASSERT_EQ(0, libc_symlink("f0", "l0"));
        ASSERT_EQ(0, libc_symlink("dhasfile/f1", "l1"));
        ASSERT_EQ(0, libc_symlink("dempty", "ldempty"));
        ASSERT_EQ(0, libc_symlink("dhasfile", "ldhasfile"));
        ASSERT_EQ(0, libc_symlink("/bin/sh", "lsh"));
        ASSERT_EQ(0, libc_symlink("/", "lroot"));
        ASSERT_EQ(0, libc_symlink(".", "l."));
        ASSERT_EQ(0, libc_symlink("..", "l.."));
        ASSERT_EQ(0, libc_symlink("/broken-symlink", "loutbroken"));
        ASSERT_EQ(0, libc_symlink("broken-symlink", "lbroken"));
        ASSERT_EQ(0, libc_symlink("x", "lx"));
        ASSERT_EQ(0, libc_symlink("y", "ly"));
        ASSERT_EQ(0, libc_symlink("z", "lz"));
        ASSERT_EQ(0, libc_symlink(mktemp(strdupa("/tmp/testXXXXXX")), "ltmp"));
        ASSERT_EQ(0, libc_symlink(mktemp(strdupa("/t/m/p/testXXXXXX")), "ltmp2"));
        errno = 0;
    }

    void TearDown() override {
        EXPECT_MAYBE_ERRNO(ENOENT, libc_chdir(basedir));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("f0"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_rmdir("dempty"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("dhasfile/f1"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_rmdir("dhasfile"));

        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("l0"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("l1"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("ldempty"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("ldhasfile"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("lsh"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("lroot"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("l."));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("l.."));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("loutbroken"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("lbroken"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("lx"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("ly"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("lz"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("ltmp"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_unlink("ltmp2"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_remove("x"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_remove("y"));
        EXPECT_MAYBE_ERRNO(ENOENT, libc_remove("z"));
    }
};

#define EXPECT_ERRNO(e, r, op)                                                              \
    do {                                                                                    \
        int oerrno = errno;                                                                 \
        auto ret = op;                                                                      \
        EXPECT_TRUE(ret == r and e == errno)                                                \
            << #op "\n"                                                                     \
            << "         retval / errno\n"                                                  \
            << "expected " << std::setw(6) << r << " / " << std::setw(5) << e << ": "       \
            << strerror(e) << "\n"                                                          \
            << "     got " << std::setw(6) << ret << " / " << std::setw(5) << errno << ": " \
            << strerror(errno);                                                             \
        errno = oerrno;                                                                     \
    } while (0)

#define EXPECT_OK(nr, op)                                     \
    do {                                                      \
        int oerrno = errno;                                   \
        auto ret = op;                                        \
        EXPECT_NE(nr, op)                                     \
            << "errno: " << errno << ": " << strerror(errno); \
        errno = oerrno;                                       \
    } while (0)

class Chdir : public SandboxTest {};

TEST_F(Chdir, ParentDirectory) {
    EXPECT_ERRNO(ESBX, -1, chdir(".."));
}

TEST_F(Chdir, SParentDirectory) {
    EXPECT_ERRNO(ESBX, -1, chdir("l.."));
}

TEST_F(Chdir, Root) {
    EXPECT_ERRNO(ESBX, -1, chdir("/"));
}

TEST_F(Chdir, SRoot) {
    EXPECT_ERRNO(ESBX, -1, chdir("lroot"));
}

TEST_F(Chdir, Here) {
    EXPECT_ERRNO(0, 0, chdir("."));
}

TEST_F(Chdir, SHere) {
    EXPECT_ERRNO(0, 0, chdir("."));
}

TEST_F(Chdir, File) {
    EXPECT_ERRNO(ENOTDIR, -1, chdir("f0"));
}

TEST_F(Chdir, SFile) {
    EXPECT_ERRNO(ENOTDIR, -1, chdir("l0"));
}

TEST_F(Chdir, EmptyString) {
    EXPECT_ERRNO(ENOENT, -1, chdir(""));
}

TEST_F(Chdir, NoSuchFile) {
    EXPECT_ERRNO(ENOENT, -1, chdir("does-not-exist"));
}

TEST_F(Chdir, BrokenSymlink) {
    EXPECT_ERRNO(ENOENT, -1, chdir("lbroken"));
}

TEST_F(Chdir, NoSuchFileOrDirectoryOutside) {
    EXPECT_ERRNO(ESBX, -1, chdir("/does/not/exist"));
}

TEST_F(Chdir, BrokenSymlinkOutside) {
    EXPECT_ERRNO(ESBX, -1, chdir("loutbroken"));
}

TEST_F(Chdir, Inside) {
    EXPECT_ERRNO(0, 0, chdir("dempty"));
    EXPECT_ERRNO(0, 0, chdir(".."));
}

TEST_F(Chdir, InsideOutside) {
    EXPECT_ERRNO(0, 0, chdir("dempty"));
    EXPECT_ERRNO(ESBX, -1, chdir("../.."));
}

class Chmod : public SandboxTest {};

TEST_F(Chmod, Inside) {
    EXPECT_ERRNO(0, 0, chmod("dhasfile", 0755));
    EXPECT_ERRNO(0, 0, chmod("dempty", 0755));
    EXPECT_ERRNO(0, 0, chmod("dhasfile/f1", 0644));
    EXPECT_ERRNO(0, 0, chmod("f0", 0644));
}

TEST_F(Chmod, SInside) {
    EXPECT_ERRNO(0, 0, chmod("l0", 0644));
    EXPECT_ERRNO(0, 0, chmod("l1", 0644));
    EXPECT_ERRNO(0, 0, chmod("ldempty", 0755));
    EXPECT_ERRNO(0, 0, chmod("ldhasfile", 0755));
}

TEST_F(Chmod, Outside) {
    EXPECT_ERRNO(ESBX, -1, chmod("..", 0755));
    EXPECT_ERRNO(ESBX, -1, chmod("/", 0755));
    EXPECT_ERRNO(ESBX, -1, chmod("/dev/null", 0755));
}

TEST_F(Chmod, SOutside) {
    EXPECT_ERRNO(ESBX, -1, chmod("lroot", 0755));
    EXPECT_ERRNO(ESBX, -1, chmod("l..", 0755));
}

TEST_F(Chmod, NoSuchFileOrDirectory) {
    EXPECT_ERRNO(ENOENT, -1, chmod("missing", 0755));
    EXPECT_ERRNO(ENOENT, -1, chmod("lbroken", 0755));
}

TEST_F(Chmod, NoSuchFileOrDirectoryOutside) {
    EXPECT_ERRNO(ENOENT, -1, chmod("/does/not/exist", 0755));
    EXPECT_ERRNO(ENOENT, -1, chmod("loutbroken", 0755));
}

class Chown : public SandboxTest {};

TEST_F(Chown, Inside) {
    EXPECT_ERRNO(0, 0, chown("dhasfile", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("dempty", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("dhasfile/f1", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("f0", getuid(), getgid()));
}

TEST_F(Chown, SInside) {
    EXPECT_ERRNO(0, 0, chown("l0", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("l1", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("ldempty", getuid(), getgid()));
    EXPECT_ERRNO(0, 0, chown("ldhasfile", getuid(), getgid()));
}

TEST_F(Chown, Outside) {
    EXPECT_ERRNO(ESBX, -1, chown("..", getuid(), getgid()));
    EXPECT_ERRNO(ESBX, -1, chown("/", getuid(), getgid()));
    EXPECT_ERRNO(ESBX, -1, chown("/dev/null", getuid(), getgid()));
}

TEST_F(Chown, SOutside) {
    EXPECT_ERRNO(ESBX, -1, chown("lroot", getuid(), getgid()));
    EXPECT_ERRNO(ESBX, -1, chown("l..", getuid(), getgid()));
}

TEST_F(Chown, NoSuchFileOrDirectory) {
    EXPECT_ERRNO(ENOENT, -1, chown("missing", getuid(), getgid()));
    EXPECT_ERRNO(ENOENT, -1, chown("lbroken", getuid(), getgid()));
}

TEST_F(Chown, NoSuchFileOrDirectoryOutside) {
    EXPECT_ERRNO(ENOENT, -1, chown("/does/not/exist", getuid(), getgid()));
    EXPECT_ERRNO(ENOENT, -1, chown("loutbroken", getuid(), getgid()));
}

class Creat : public SandboxTest {};

TEST_F(Creat, IsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, creat("dhasfile", 0644));
    EXPECT_ERRNO(EISDIR, -1, creat("dempty", 0644));
}

TEST_F(Creat, LinkIsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, creat("ldhasfile", 0644));
    EXPECT_ERRNO(EISDIR, -1, creat("ldempty", 0644));
}

TEST_F(Creat, Exists) {
    EXPECT_OK(-1, creat("f0", 0644));
    EXPECT_OK(-1, creat("dhasfile/f1", 0644));
}

TEST_F(Creat, LinkExists) {
    EXPECT_OK(-1, creat("l0", 0644));
    EXPECT_OK(-1, creat("l1", 0644));
}

TEST_F(Creat, Outside) {
    EXPECT_ERRNO(ESBX, -1, creat("/tmp/creat-outside", 0644));
}

TEST_F(Creat, OutsideDir) {
    EXPECT_ERRNO(ESBX, -1, creat("/tmp/does/not/exist/outside", 0644));
}

TEST_F(Creat, NormalOperation) {
    EXPECT_OK(-1, creat("x", 0644));
}

TEST_F(Creat, NormalOperationOnLink) {
    EXPECT_OK(-1, creat("lx", 0644));
}

TEST_F(Creat, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, creat("ltmp", 0644));
}

TEST_F(Creat, LinkOutsideND) {
    EXPECT_ERRNO(ESBX, -1, creat("ltmp2", 0644));
}

class FopenW : public SandboxTest {};

TEST_F(FopenW, IsADirectory) {
    EXPECT_ERRNO(EISDIR, (FILE *)nullptr, fopen("dhasfile", "w"));
    EXPECT_ERRNO(EISDIR, (FILE *)nullptr, fopen("dempty", "w"));
}

TEST_F(FopenW, LinkIsADirectory) {
    EXPECT_ERRNO(EISDIR, (FILE *)nullptr, fopen("ldhasfile", "w"));
    EXPECT_ERRNO(EISDIR, (FILE *)nullptr, fopen("ldempty", "w"));
}

TEST_F(FopenW, Exists) {
    EXPECT_OK((FILE *)nullptr, fopen("f0", "w"));
    EXPECT_OK((FILE *)nullptr, fopen("dhasfile/f1", "w"));
}

TEST_F(FopenW, LinkExists) {
    EXPECT_OK((FILE *)nullptr, fopen("l0", "w"));
    EXPECT_OK((FILE *)nullptr, fopen("l1", "w"));
}

TEST_F(FopenW, Outside) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("/tmp/fopen-outside", "w"));
}

TEST_F(FopenW, OutsideDir) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("/tmp/does/not/exist/outside", "w"));
}

TEST_F(FopenW, NormalOperation) {
    EXPECT_OK((FILE *)nullptr, fopen("x", "w"));
}

TEST_F(FopenW, NormalOperationOnLink) {
    EXPECT_OK((FILE *)nullptr, fopen("lx", "w"));
}

TEST_F(FopenW, LinkOutside) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("ltmp", "w"));
}

TEST_F(FopenW, LinkOutsideND) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("ltmp2", "w"));
}

class FopenA : public SandboxTest {};

TEST_F(FopenA, IsADirectory) {
    EXPECT_ERRNO(EISDIR, (FILE *)nullptr, fopen("dhasfile", "a"));
    EXPECT_ERRNO(EISDIR, (FILE *)nullptr, fopen("dempty", "a"));
}

TEST_F(FopenA, LinkIsADirectory) {
    EXPECT_ERRNO(EISDIR, (FILE *)nullptr, fopen("ldhasfile", "a"));
    EXPECT_ERRNO(EISDIR, (FILE *)nullptr, fopen("ldempty", "a"));
}

TEST_F(FopenA, Exists) {
    EXPECT_OK((FILE *)nullptr, fopen("f0", "a"));
    EXPECT_OK((FILE *)nullptr, fopen("dhasfile/f1", "a"));
}

TEST_F(FopenA, LinkExists) {
    EXPECT_OK((FILE *)nullptr, fopen("l0", "a"));
    EXPECT_OK((FILE *)nullptr, fopen("l1", "a"));
}

TEST_F(FopenA, Outside) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("/tmp/fopen-outside", "a"));
}

TEST_F(FopenA, OutsideDir) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("/tmp/does/not/exist/outside", "a"));
}

TEST_F(FopenA, NormalOperation) {
    EXPECT_OK((FILE *)nullptr, fopen("x", "a"));
}

TEST_F(FopenA, NormalOperationOnLink) {
    EXPECT_OK((FILE *)nullptr, fopen("lx", "a"));
}

TEST_F(FopenA, LinkOutside) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("ltmp", "a"));
}

TEST_F(FopenA, LinkOutsideND) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("ltmp2", "a"));
}

class FopenR : public SandboxTest {};

TEST_F(FopenR, Exists) {
    EXPECT_OK((FILE *)nullptr, fopen("f0", "r"));
    EXPECT_OK((FILE *)nullptr, fopen("dhasfile/f1", "r"));
}

TEST_F(FopenR, LinkExists) {
    EXPECT_OK((FILE *)nullptr, fopen("l0", "r"));
    EXPECT_OK((FILE *)nullptr, fopen("l1", "r"));
}

TEST_F(FopenR, Outside) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("/dev/null", "r"));
}

TEST_F(FopenR, LinkOutside) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("lsh", "r"));
}

TEST_F(FopenR, LinkOutsideDoesNotExist) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("loutbroken", "r"));
}

TEST_F(FopenR, DoesNotExist) {
    EXPECT_ERRNO(ENOENT, (FILE *)nullptr, fopen("x", "r"));
}

TEST_F(FopenR, NormalOperationOnLink) {
    EXPECT_ERRNO(ENOENT, (FILE *)nullptr, fopen("lx", "r"));
}

TEST_F(FopenR, LinkOutsideDoesNotExistTmp) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("ltmp", "r"));
}

TEST_F(FopenR, LinkOutsideDoesNotExistTmp2) {
    EXPECT_ERRNO(ESBX, (FILE *)nullptr, fopen("ltmp2", "r"));
}

class Link : public SandboxTest {};

TEST_F(Link, NormalOperation) {
    EXPECT_ERRNO(0, 0, link("f0", "x"));
    EXPECT_ERRNO(0, 0, link("dhasfile/f1", "y"));
}

TEST_F(Link, OnSymlink) {
    EXPECT_ERRNO(EEXIST, -1, link("f0", "ltmp"));
}

TEST_F(Link, Directory) {
    EXPECT_ERRNO(EPERM, -1, link("dempty", "x"));
}

TEST_F(Link, Path2Outside) {
    EXPECT_ERRNO(ESBX, -1, link("f0", mktemp(strdupa("/tmp/testXXXXXX"))));
}

TEST_F(Link, Path1Outside) {
    EXPECT_ERRNO(ESBX, -1, link("/bin/sh", "x"));
}

class OpenW : public SandboxTest {};

TEST_F(OpenW, IsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, open("dhasfile", O_CREAT | O_WRONLY, 0644));
    EXPECT_ERRNO(EISDIR, -1, open("dempty", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, LinkIsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, open("ldhasfile", O_CREAT | O_WRONLY, 0644));
    EXPECT_ERRNO(EISDIR, -1, open("ldempty", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, Exists) {
    EXPECT_OK(-1, open("f0", O_CREAT | O_WRONLY, 0644));
    EXPECT_OK(-1, open("dhasfile/f1", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, LinkExists) {
    EXPECT_OK(-1, open("l0", O_CREAT | O_WRONLY, 0644));
    EXPECT_OK(-1, open("l1", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, ExistsExcl) {
    EXPECT_ERRNO(EEXIST, -1, open("f0", O_CREAT | O_WRONLY | O_EXCL, 0644));
    EXPECT_ERRNO(EEXIST, -1, open("dhasfile/f1", O_CREAT | O_WRONLY | O_EXCL, 0644));
}

TEST_F(OpenW, LinkExistsExcl) {
    EXPECT_ERRNO(EEXIST, -1, open("l0", O_CREAT | O_WRONLY | O_EXCL, 0644));
    EXPECT_ERRNO(EEXIST, -1, open("l1", O_CREAT | O_WRONLY | O_EXCL, 0644));
}

TEST_F(OpenW, Outside) {
    EXPECT_ERRNO(ESBX, -1, open("/tmp/open-outside", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, OutsideDir) {
    EXPECT_ERRNO(ESBX, -1, open("/tmp/does/not/exist/outside", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, NormalOperation) {
    EXPECT_OK(-1, open("x", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, NormalOperationOnLink) {
    EXPECT_OK(-1, open("lx", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, open("ltmp", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenW, LinkOutsideND) {
    EXPECT_ERRNO(ESBX, -1, open("ltmp2", O_CREAT | O_WRONLY, 0644));
}

class OpenR : public SandboxTest {};

TEST_F(OpenR, Exists) {
    EXPECT_OK(-1, open("f0", O_RDONLY));
    EXPECT_OK(-1, open("dhasfile/f1", O_RDONLY));
}

TEST_F(OpenR, LinkExists) {
    EXPECT_OK(-1, open("l0", O_RDONLY));
    EXPECT_OK(-1, open("l1", O_RDONLY));
}

TEST_F(OpenR, Outside) {
    EXPECT_ERRNO(ESBX, -1, open("/dev/null", O_RDONLY));
}

TEST_F(OpenR, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, open("lsh", O_RDONLY));
}

TEST_F(OpenR, LinkOutsideDoesNotExist) {
    EXPECT_ERRNO(ESBX, -1, open("loutbroken", O_RDONLY));
}

TEST_F(OpenR, DoesNotExist) {
    EXPECT_ERRNO(ENOENT, -1, open("x", O_RDONLY));
}

TEST_F(OpenR, NormalOperationOnLink) {
    EXPECT_ERRNO(ENOENT, -1, open("lx", O_RDONLY));
}

TEST_F(OpenR, LinkOutsideDoesNotExistTmp) {
    EXPECT_ERRNO(ESBX, -1, open("ltmp", O_RDONLY));
}

TEST_F(OpenR, LinkOutsideDoesNotExistTmp2) {
    EXPECT_ERRNO(ESBX, -1, open("ltmp2", O_RDONLY));
}

class OpenAtW : public SandboxTest {};

TEST_F(OpenAtW, IsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, openat(AT_FDCWD, "dhasfile", O_CREAT | O_WRONLY, 0644));
    EXPECT_ERRNO(EISDIR, -1, openat(AT_FDCWD, "dempty", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, LinkIsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, openat(AT_FDCWD, "ldhasfile", O_CREAT | O_WRONLY, 0644));
    EXPECT_ERRNO(EISDIR, -1, openat(AT_FDCWD, "ldempty", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, Exists) {
    EXPECT_OK(-1, openat(AT_FDCWD, "f0", O_CREAT | O_WRONLY, 0644));
    EXPECT_OK(-1, openat(AT_FDCWD, "dhasfile/f1", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, LinkExists) {
    EXPECT_OK(-1, openat(AT_FDCWD, "l0", O_CREAT | O_WRONLY, 0644));
    EXPECT_OK(-1, openat(AT_FDCWD, "l1", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, ExistsExcl) {
    EXPECT_ERRNO(EEXIST, -1, openat(AT_FDCWD, "f0", O_CREAT | O_WRONLY | O_EXCL, 0644));
    EXPECT_ERRNO(EEXIST, -1, openat(AT_FDCWD, "dhasfile/f1", O_CREAT | O_WRONLY | O_EXCL, 0644));
}

TEST_F(OpenAtW, LinkExistsExcl) {
    EXPECT_ERRNO(EEXIST, -1, openat(AT_FDCWD, "l0", O_CREAT | O_WRONLY | O_EXCL, 0644));
    EXPECT_ERRNO(EEXIST, -1, openat(AT_FDCWD, "l1", O_CREAT | O_WRONLY | O_EXCL, 0644));
}

TEST_F(OpenAtW, Outside) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "/tmp/open-outside", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, OutsideDir) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "/tmp/does/not/exist/outside", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, NormalOperation) {
    EXPECT_OK(-1, openat(AT_FDCWD, "x", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, NormalOperationOnLink) {
    EXPECT_OK(-1, openat(AT_FDCWD, "lx", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "ltmp", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtW, LinkOutsideND) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "ltmp2", O_CREAT | O_WRONLY, 0644));
}

class OpenAtR : public SandboxTest {};

TEST_F(OpenAtR, Exists) {
    EXPECT_OK(-1, openat(AT_FDCWD, "f0", O_RDONLY));
    EXPECT_OK(-1, openat(AT_FDCWD, "dhasfile/f1", O_RDONLY));
}

TEST_F(OpenAtR, LinkExists) {
    EXPECT_OK(-1, openat(AT_FDCWD, "l0", O_RDONLY));
    EXPECT_OK(-1, openat(AT_FDCWD, "l1", O_RDONLY));
}

TEST_F(OpenAtR, Outside) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "/dev/null", O_RDONLY));
}

TEST_F(OpenAtR, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "lsh", O_RDONLY));
}

TEST_F(OpenAtR, LinkOutsideDoesNotExist) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "loutbroken", O_RDONLY));
}

TEST_F(OpenAtR, DoesNotExist) {
    EXPECT_ERRNO(ENOENT, -1, openat(AT_FDCWD, "x", O_RDONLY));
}

TEST_F(OpenAtR, NormalOperationOnLink) {
    EXPECT_ERRNO(ENOENT, -1, openat(AT_FDCWD, "lx", O_RDONLY));
}

TEST_F(OpenAtR, LinkOutsideDoesNotExistTmp) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "ltmp", O_RDONLY));
}

TEST_F(OpenAtR, LinkOutsideDoesNotExistTmp2) {
    EXPECT_ERRNO(ESBX, -1, openat(AT_FDCWD, "ltmp2", O_RDONLY));
}

class OpenAtTestRoot : public SandboxTest {
  protected:
    int at_troot;

  public:
    void SetUp() override {
        SandboxTest::SetUp();
        EXPECT_OK(-1, at_troot = libc_open(basedir, O_RDONLY));
        EXPECT_OK(-1, libc_chdir("dhasfile"));
    }
    void TearDown() override {
        SandboxTest::TearDown();
        ASSERT_EQ(0, close(at_troot));
    }
};

class OpenAtTestRootW : public OpenAtTestRoot {};

TEST_F(OpenAtTestRootW, IsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, openat(at_troot, "dhasfile", O_CREAT | O_WRONLY, 0644));
    EXPECT_ERRNO(EISDIR, -1, openat(at_troot, "dempty", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, LinkIsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, openat(at_troot, "ldhasfile", O_CREAT | O_WRONLY, 0644));
    EXPECT_ERRNO(EISDIR, -1, openat(at_troot, "ldempty", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, Exists) {
    EXPECT_OK(-1, openat(at_troot, "f0", O_CREAT | O_WRONLY, 0644));
    EXPECT_OK(-1, openat(at_troot, "dhasfile/f1", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, LinkExists) {
    EXPECT_OK(-1, openat(at_troot, "l0", O_CREAT | O_WRONLY, 0644));
    EXPECT_OK(-1, openat(at_troot, "l1", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, ExistsExcl) {
    EXPECT_ERRNO(EEXIST, -1, openat(at_troot, "f0", O_CREAT | O_WRONLY | O_EXCL, 0644));
    EXPECT_ERRNO(EEXIST, -1, openat(at_troot, "dhasfile/f1", O_CREAT | O_WRONLY | O_EXCL, 0644));
}

TEST_F(OpenAtTestRootW, LinkExistsExcl) {
    EXPECT_ERRNO(EEXIST, -1, openat(at_troot, "l0", O_CREAT | O_WRONLY | O_EXCL, 0644));
    EXPECT_ERRNO(EEXIST, -1, openat(at_troot, "l1", O_CREAT | O_WRONLY | O_EXCL, 0644));
}

TEST_F(OpenAtTestRootW, Outside) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "/tmp/open-outside", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, OutsideDir) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "/tmp/does/not/exist/outside", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, NormalOperation) {
    EXPECT_OK(-1, openat(at_troot, "x", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, NormalOperationOnLink) {
    EXPECT_OK(-1, openat(at_troot, "lx", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "ltmp", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtTestRootW, LinkOutsideND) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "ltmp2", O_CREAT | O_WRONLY, 0644));
}

class OpenAtTestRootR : public OpenAtTestRoot {};

TEST_F(OpenAtTestRootR, Exists) {
    EXPECT_OK(-1, openat(at_troot, "f0", O_RDONLY));
    EXPECT_OK(-1, openat(at_troot, "dhasfile/f1", O_RDONLY));
}

TEST_F(OpenAtTestRootR, LinkExists) {
    EXPECT_OK(-1, openat(at_troot, "l0", O_RDONLY));
    EXPECT_OK(-1, openat(at_troot, "l1", O_RDONLY));
}

TEST_F(OpenAtTestRootR, Outside) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "/dev/null", O_RDONLY));
}

TEST_F(OpenAtTestRootR, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "lsh", O_RDONLY));
}

TEST_F(OpenAtTestRootR, LinkOutsideDoesNotExist) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "loutbroken", O_RDONLY));
}

TEST_F(OpenAtTestRootR, DoesNotExist) {
    EXPECT_ERRNO(ENOENT, -1, openat(at_troot, "x", O_RDONLY));
}

TEST_F(OpenAtTestRootR, NormalOperationOnLink) {
    EXPECT_ERRNO(ENOENT, -1, openat(at_troot, "lx", O_RDONLY));
}

TEST_F(OpenAtTestRootR, LinkOutsideDoesNotExistTmp) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "ltmp", O_RDONLY));
}

TEST_F(OpenAtTestRootR, LinkOutsideDoesNotExistTmp2) {
    EXPECT_ERRNO(ESBX, -1, openat(at_troot, "ltmp2", O_RDONLY));
}

class OpenAtSubDir : public SandboxTest {
  protected:
    int at_subd;

  public:
    void SetUp() override {
        SandboxTest::SetUp();
        EXPECT_OK(-1, at_subd = libc_open("dhasfile", O_RDONLY));
    }
    void TearDown() override {
        SandboxTest::TearDown();
        ASSERT_EQ(0, close(at_subd));
    }
};

class OpenAtSubDirW : public OpenAtSubDir {};

TEST_F(OpenAtSubDirW, IsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, openat(at_subd, "../dhasfile", O_CREAT | O_WRONLY, 0644));
    EXPECT_ERRNO(EISDIR, -1, openat(at_subd, "../dempty", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtSubDirW, LinkIsADirectory) {
    EXPECT_ERRNO(EISDIR, -1, openat(at_subd, "../ldhasfile", O_CREAT | O_WRONLY, 0644));
    EXPECT_ERRNO(EISDIR, -1, openat(at_subd, "../ldempty", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtSubDirW, Exists) {
    EXPECT_OK(-1, openat(at_subd, "../f0", O_CREAT | O_WRONLY, 0644));
    EXPECT_OK(-1, openat(at_subd, "f1", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtSubDirW, LinkExists) {
    EXPECT_OK(-1, openat(at_subd, "../l0", O_CREAT | O_WRONLY, 0644));
    EXPECT_OK(-1, openat(at_subd, "../l1", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtSubDirW, ExistsExcl) {
    EXPECT_ERRNO(EEXIST, -1, openat(at_subd, "../f0", O_CREAT | O_WRONLY | O_EXCL, 0644));
    EXPECT_ERRNO(EEXIST, -1, openat(at_subd, "f1", O_CREAT | O_WRONLY | O_EXCL, 0644));
}

TEST_F(OpenAtSubDirW, LinkExistsExcl) {
    EXPECT_ERRNO(EEXIST, -1, openat(at_subd, "../l0", O_CREAT | O_WRONLY | O_EXCL, 0644));
    EXPECT_ERRNO(EEXIST, -1, openat(at_subd, "../l1", O_CREAT | O_WRONLY | O_EXCL, 0644));
}

TEST_F(OpenAtSubDirW, NormalOperation) {
    EXPECT_OK(-1, openat(at_subd, "../x", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtSubDirW, NormalOperationOnLink) {
    EXPECT_OK(-1, openat(at_subd, "../lx", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtSubDirW, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, openat(at_subd, "../ltmp", O_CREAT | O_WRONLY, 0644));
}

TEST_F(OpenAtSubDirW, LinkOutsideND) {
    EXPECT_ERRNO(ESBX, -1, openat(at_subd, "../ltmp2", O_CREAT | O_WRONLY, 0644));
}

class OpenAtSubDirR : public OpenAtSubDir {};

TEST_F(OpenAtSubDirR, Exists) {
    EXPECT_OK(-1, openat(at_subd, "../f0", O_RDONLY));
    EXPECT_OK(-1, openat(at_subd, "f1", O_RDONLY));
}

TEST_F(OpenAtSubDirR, LinkExists) {
    EXPECT_OK(-1, openat(at_subd, "../l0", O_RDONLY));
    EXPECT_OK(-1, openat(at_subd, "../l1", O_RDONLY));
}

TEST_F(OpenAtSubDirR, LinkOutside) {
    EXPECT_ERRNO(ESBX, -1, openat(at_subd, "../lsh", O_RDONLY));
}

TEST_F(OpenAtSubDirR, LinkOutsideDoesNotExist) {
    EXPECT_ERRNO(ESBX, -1, openat(at_subd, "../loutbroken", O_RDONLY));
}

TEST_F(OpenAtSubDirR, DoesNotExist) {
    EXPECT_ERRNO(ENOENT, -1, openat(at_subd, "../x", O_RDONLY));
}

TEST_F(OpenAtSubDirR, NormalOperationOnLink) {
    EXPECT_ERRNO(ENOENT, -1, openat(at_subd, "../lx", O_RDONLY));
}

TEST_F(OpenAtSubDirR, LinkOutsideDoesNotExistTmp) {
    EXPECT_ERRNO(ESBX, -1, openat(at_subd, "../ltmp", O_RDONLY));
}

TEST_F(OpenAtSubDirR, LinkOutsideDoesNotExistTmp2) {
    EXPECT_ERRNO(ESBX, -1, openat(at_subd, "../ltmp2", O_RDONLY));
}

class Exec : public SandboxTest {};

char fail_msg[] = "ERROR: EXEC BYPASSED SANDBOX";
char binecho[] = "/bin/echo";
char *exec_args[] = {binecho, fail_msg, 0};

TEST_F(Exec, Execl) {
    EXPECT_ERRNO(ESBX, -1, execl("/bin/echo", "echo", fail_msg, 0));
}

TEST_F(Exec, Execle) {
    EXPECT_ERRNO(ESBX, -1, execle("/bin/echo", "echo", fail_msg, 0, environ));
}

TEST_F(Exec, Execlp) {
    EXPECT_ERRNO(ESBX, -1, execlp("echo", "echo", fail_msg, 0));
    EXPECT_ERRNO(ESBX, -1, execlp("/bin/echo", "echo", fail_msg, 0));
}

TEST_F(Exec, Execv) { EXPECT_ERRNO(ESBX, -1, execv(binecho, exec_args)); }

TEST_F(Exec, Execve) {
    EXPECT_ERRNO(ESBX, -1, execve("/bin/echo", exec_args, environ));
}

TEST_F(Exec, Execvp) {
    EXPECT_ERRNO(ESBX, -1, execvp("echo", exec_args));
    EXPECT_ERRNO(ESBX, -1, execvp("/bin/echo", exec_args));
}

TEST_F(Exec, System) {
    EXPECT_ERRNO(ESBX, -1, system("echo ERROR: EXEC BYPASSED SANDBOX"));
}
